use std::io::Read;
use std::iter;
use ff::PrimeFieldBits;
use group::Curve;
use itertools::Itertools;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas::Base;
use crate::state::State;

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
#[derive(Default, Copy, Clone)]
pub struct Instruction {
    pub addr: u32,
    pub bytecode: u32,
}

impl Instruction {
    fn to_bits(&self) -> [bool; 32] {
        i2lebsp::<32>(self.bytecode as u64) // omit the high 4 bits of address
    }
}


#[derive(Default, Clone)]
pub struct ProgramSegment {
    pub start_addr: u32,
    pub segment_size: u32,
    pub instructions: Vec<Instruction>,
}


#[derive(Default, Clone)]
pub struct Program {
    cur_segment: usize,
    cur_instruction: usize,
    cur_bit: usize, // each instruction has 32 bits
    pub segments: Vec<ProgramSegment>
}

pub const PERSONALIZATION: &str = "ProgramCRH";

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
            if self.cur_bit == 32 {
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

    // side effect: change iterator variables
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

    pub fn compute_hash(&mut self) -> Base {
        use super::sinsemilla::HashDomain;
        let hasher = HashDomain::new(PERSONALIZATION);

        let init = hasher.Q.to_affine()
            .coordinates()
            .map(|c| *c.x()).unwrap();

        let mut a0 = init;

        // each time take 60 instructions
        // init: a0 to Q
        // a0  = hash(a0 | 60 * 32 bits instruction)
        for chunk in &self.into_iter().chunks(60 * 32) {
            a0 = hasher.hash(
                iter::empty()
                    .chain(a0.to_le_bits().into_iter().take(250))
                    .chain(chunk.into_iter())
            ).unwrap();
        }
        a0
    }
}


#[derive(Copy, Clone)]
pub struct ExecutionRow {
    pub instruction: Instruction,
    pub step: u32,
    pub registers: [u32; 32],
    pub pc: u32,
    pub next_pc: u32,
    pub heap: u32,
    pub exited: bool,
}


#[derive(Copy, Clone)]
pub enum MemoryOperation {
    Read,
    Write,
}


#[derive(Copy, Clone)]
pub struct MemoryAccess {
    pub addr: u32,
    pub op: MemoryOperation,
    pub value: u32,
}


#[derive(Default, Clone)]
pub struct Trace {
    pub prog: Program,  // program table
    pub exec: Vec<ExecutionRow>,  // executed instructions
    pub mem: Vec<MemoryAccess>,   // memory access table
}
