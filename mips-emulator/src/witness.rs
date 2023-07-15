use std::io::Read;
use std::iter;
use ff::PrimeFieldBits;
use group::Curve;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas::Base;
use crate::state::State;
use super::sinsemilla::HashDomain;

/// StepWitness is for fault proof in OP stack.
#[derive(Default)]
pub struct StepWitness {
    // encoded state witness
    pub state: Vec<u8>,
    pub mem_proof: Vec<u8>,

    pub preimage_key: [u8; 32], // zeroed when no pre-image is accessed
    pub preimage_value: Vec<u8>, // including the 8-byte length prefix
    pub preimage_offset: u32,
}

const MIPS_INSTRUCTION_LEN: usize = 32;
const MIPS_REGISTERS_NUM: usize = 32;
const HASH_OUTPUT_TAKE_LEN: usize = 250;
const HASH_CHUNK_LEN: usize = 60;

/// Convert a u64 `integer` to a bit array with length `NUM_BITS`.
/// The bit array will be arranged from low to high.
/// For example, given `integer` 234 and `NUM_BITS` 8
/// The binary representation is '0b11101010', the returned value will be
/// `[0, 1, 0, 1, 0, 1, 1, 1]`
pub fn i2lebsp<const NUM_BITS: usize>(int: u64) -> [bool; NUM_BITS] {
    /// Takes in an FnMut closure and returns a constant-length array with elements of
    /// type `Output`.
    fn gen_const_array<Output: Copy + Default, const LEN: usize>(
        closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        let mut ret: [Output; LEN] = [Default::default(); LEN];
        for (bit, val) in ret.iter_mut().zip((0..LEN).map(closure)) {
            *bit = val;
        }
        ret
    }
    assert!(NUM_BITS <= 64);
    gen_const_array(|mask: usize| (int & (1 << mask)) != 0)
}


/// MIPS Instruction, it is fixed length, i.e., 32-bits.
#[derive(Default, Copy, Clone, Debug)]
pub struct Instruction {
    pub addr: u32,
    pub bytecode: u32,
}


impl Instruction {
    fn to_bits(&self) -> [bool; MIPS_INSTRUCTION_LEN] {
        i2lebsp::<MIPS_INSTRUCTION_LEN>(self.bytecode as u64) // omit the high 4 bits of address
    }
}


/// ProgramSegment is a segment of program, it contains the start address and size of
/// the segment, and all the instructions in the segment.
#[derive(Default, Clone)]
pub struct ProgramSegment {
    pub start_addr: u32,
    pub segment_size: u32,
    pub instructions: Vec<Instruction>,
}

/// The program struct consists of all the segments.
/// The `cur_segment`, `cur_instruction`, `cur_bit` variable are used to
/// iterate the instructions of the program, to compute the program hash.
#[derive(Default, Clone)]
pub struct Program {
    cur_segment: usize,
    cur_instruction: usize,
    cur_bit: usize, // each instruction has 32 bits
    pub segments: Vec<ProgramSegment>
}


/// To initialize the Sinsemilla hasher, it is a math parameter.
pub const PERSONALIZATION: &str = "zkMIPS-CRH";


impl Iterator for Program {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        let cur_segment = self.cur_segment;
        let cur_instruction = self.cur_instruction;
        let cur_bit = self.cur_bit;

        let res = if cur_segment >= self.segments.len() {
            None
        } else {
            let ins = self.segments[cur_segment].instructions[cur_instruction];
            let bit = ins.to_bits()[cur_bit];

            self.cur_bit += 1;
            if self.cur_bit == MIPS_INSTRUCTION_LEN {
                self.cur_bit = 0;
                self.cur_instruction += 1;
                if self.cur_instruction == self.segments[cur_segment].instructions.len() {
                    self.cur_instruction = 0;
                    self.cur_segment += 1;
                }
            }
            Some(bit)
        };

        res
    }
}


impl Program {
    pub fn new() -> Self {
        Self {
            cur_segment: 0,
            cur_instruction: 0,
            cur_bit: 0,
            segments: vec![],
        }
    }

    pub fn load_instructions(&mut self, state: &mut Box<State>) {
        for i in 0..self.segments.len() {
            let segment = &mut self.segments[i];
            let mut buf = Vec::<u8>::new();
            state.memory.read_memory_range(segment.start_addr, segment.segment_size);
            state.memory.read_to_end(&mut buf).unwrap();

            // Here we assume instructions aligned with 4 bytes, this is reasonable, because
            // the MIPS instruction is fixed length with 4 bytes.
            // Note here we may read some data segments into the Program struct, it is ok, because
            // we use program to compute hash for integrity and load the program to halo2 table for
            // instruction lookup, load data segments won't have effect.
            for i in (0..buf.len()).step_by(4) {
                segment.instructions.push(Instruction {
                    addr: segment.start_addr + (i as u32),
                    bytecode: u32::from_le_bytes(buf[i..i+4].try_into().unwrap())
                });
            }
        }
    }

    pub fn reset_iterator(&mut self) {
        self.cur_segment = 0;
        self.cur_instruction = 0;
        self.cur_bit = 0;
    }

    pub fn total_instructions(&self) -> usize {
        let mut sum = 0;
        for i in 0..self.segments.len() {
            sum += self.segments[i].instructions.len();
        }
        sum
    }

    /// Fetch the next instruction, it is different the Iterator trait cause next method get
    /// a single bit of instruction, the `next_instruction` method gets the next instruction
    /// with 4 bytes.
    /// `cur_segment` and `cur_instruction` variable are passed in. The method also returns
    /// the updated `cur_segment` and `cur_instruction` as `res_segment` and `res_instruction`.
    /// If read to the end, then the method returns `None`, otherwise returns `Instruction`.
    /// The method has side effect: changing iterator variables, after using
    /// should invoke `reset_iterator`.
    pub fn next_instruction(&self,
                            cur_segment: usize,
                            cur_instruction: usize) -> (Option<Instruction>, usize, usize) {

        let mut res_segment = cur_segment;
        let mut res_instruction = cur_instruction;

        let res = if res_segment >= self.segments.len() {
            (None, res_segment, res_instruction)
        } else {
            let ins = self.segments[res_segment].instructions[res_instruction];

            res_instruction += 1;
            if res_instruction == self.segments[res_segment].instructions.len() {
                res_instruction = 0;
                res_segment += 1;
            }

            (Some(ins), res_segment, res_instruction)
        };

        res
    }

    /// Compute the Sinsemilla hash of the program, to commit the program.
    /// Further to attestation that the prover run the committed program corresponding to the hash.
    /// *Why Sinsemilla Hash*
    /// 1. The Sinsemilla hash is designed for the lookup argument, it used a size 1024 lookup table,
    /// proving the correct execution of Sinsemilla is faster than Poseidon, Recue, SHA in halo2.
    ///
    /// 2. The Sinsemilla instance accepts a point for initializing, we can construct such a point
    /// from a short string, here we use `PERSONALIZATION` string.
    ///
    /// 3. The Sinsemilla hash splits the input into `N` chunks, each chunk is 10 bits, implying
    /// the input's bits length should be multiple of 10. Limited by math group size, it can not
    /// accepts input with unlimited length. Currently the `N` is at most `253`, But this does not
    /// mean we can give the input at most 2530 bits. In the following proving stage we also put
    /// the input into halo2 cells, each cells is `pasta` or `bn256` base field, that means we can
    /// at most make input be 250 bits, and at most 10 cells.
    ///
    /// *How compute*
    /// Each instructions is 32 bits, we take 60 instructions as a chunk, the chunk is 32 * 60 = 1920
    /// bits. For each chunk, we split them to element that can put into halo2 cell. Each element is
    /// 240 bits, 7.5 * 32 = 240 bit, 240 * 8 = 32 * 60, so we split a chunk into 8 cells.
    ///
    /// Initializing the a0 to Q.x, which is a 255 bits value, we omit the high 5 bits, take the low
    /// 250 bits, and then we take `a0 | 8 cells` as inputs and get output 255 bits.
    /// For circuit simplicity, we omit the high 5 bits, so we take the low 250 bits, the next round
    /// is `output[..250] | 8 cells`, until we compute all the program.
    ///
    /// If the program instructions count is not multiple of 60, we just pad zeros.
    pub fn compute_hash(&mut self) -> Base {
        let hasher = HashDomain::new(&format!("{}-M", PERSONALIZATION));

        let init = hasher.Q.to_affine()
            .coordinates()
            .map(|c| *c.x()).unwrap();

        let mut a0 = init;

        // fetch 120 instructions, if less than 120, then pad with zeros
        let (mut cur_segment, mut cur_instruction) = (0, 0);
        let mut fetch_chunk_120 = || {
            let mut cnt = 0;
            let mut chunk = vec![];
            let mut done: bool = false;
            loop {
                match self.next_instruction(cur_segment, cur_instruction) {
                    (None, _, _) => {
                        break
                    },
                    (Some(instruction), cursor1, cursor2) => {
                        (cur_segment, cur_instruction) = (cursor1, cursor2);
                        chunk.push(instruction.bytecode);
                        cnt += 1;
                        if cnt >= 120 {
                            break
                        }
                    }
                }
            }
            if chunk.len() < 120 {
                for _ in chunk.len()..120 {
                    chunk.push(0);
                }
                done = true;
            }
            (chunk, done)
        };

        let mut all_instructions: Vec<u32> = vec![];
        loop {
            let (chunk, done) = fetch_chunk_120();
            all_instructions.extend(chunk);
            if done {
                break;
            }
        }

        let mut idx = 0;
        loop {
            let mut chunk: Vec<bool> = vec![];

            // HASH_CHUNK_LEN = 8 * 7.5 = 4 * 15
            for i in 0..4 {
                let mut sub_chunk: Vec<Vec<bool>> = vec![];
                for j in 0..7 {
                    sub_chunk.push(
                        i2lebsp::<MIPS_INSTRUCTION_LEN>(
                            all_instructions[idx+i*15+j] as u64
                        ).try_into().unwrap()
                    );
                }
                let mid_one_bits = i2lebsp::<MIPS_INSTRUCTION_LEN>(
                    all_instructions[idx+i*15+7] as u64);
                sub_chunk.push(
                    mid_one_bits[..MIPS_INSTRUCTION_LEN/2].try_into().unwrap()
                );
                for j in (0..sub_chunk.len()).rev() {
                    chunk.extend(&sub_chunk[j]);
                }

                let mut sub_chunk: Vec<Vec<bool>> = vec![];
                sub_chunk.push(
                    mid_one_bits[MIPS_INSTRUCTION_LEN/2..].try_into().unwrap()
                );
                for j in 8..15 {
                    sub_chunk.push(
                        i2lebsp::<MIPS_INSTRUCTION_LEN>(
                            all_instructions[idx+i*15+j] as u64
                        ).try_into().unwrap()
                    );
                }
                for j in (0..sub_chunk.len()).rev() {
                    chunk.extend(&sub_chunk[j]);
                }
            }

            idx += HASH_CHUNK_LEN;

            a0 = hasher.hash(
                iter::empty()
                    .chain(a0.to_le_bits().into_iter().take(HASH_OUTPUT_TAKE_LEN))
                    .chain(chunk.into_iter())
            ).unwrap();

            if idx >= all_instructions.len() {
                break
            }
        }
        a0
    }
}


/// ExecutionRow contains a instruction executed, and the registers state after execution
/// pc, next_pc, heap and exited flag.
#[derive(Copy, Clone, Default, Debug)]
pub struct ExecutionRow {
    pub instruction: Instruction,
    pub step: u64,
    pub registers: [u32; MIPS_REGISTERS_NUM],
    pub pc: u32,
    pub next_pc: u32,
    pub heap: u32,
    pub exited: bool,
    pub hi: u32,
    pub lo: u32,
}


/// Operation to memory access, Read/Write
#[derive(Copy, Clone, Debug)]
pub enum MemoryOperation {
    Read,
    Write,
}


/// A memory access, contains the address, operation type, and the value returns.
/// If the access is Read, then `value` is the read result.
/// If the access is Write, then `value` is the write value.
#[derive(Copy, Clone, Debug)]
pub struct MemoryAccess {
    pub addr: u32,
    pub op: MemoryOperation,
    pub value: u32,
}


/// Trace is the input to zk prover, which means we can separate the vm execution
/// and proof generation.
/// The trace contains the program struct, the execution trace list, the memory access list.
#[derive(Default, Clone)]
pub struct Trace {
    pub prog: Program,            // program table
    pub exec: Vec<ExecutionRow>,  // executed instructions
    pub mem: Vec<MemoryAccess>,   // memory access table
}
