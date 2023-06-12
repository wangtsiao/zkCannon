use std::io::Write;
use crate::memory::Memory;
use crate::page::{PAGE_ADDR_MASK, PAGE_SIZE};
use log::debug;
use std::cmp::min;

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_HINT_READ: u32 = 3;
pub const FD_HINT_WRITE: u32 = 4;
pub const FD_PREIMAGE_READ: u32 = 5;
pub const FD_PREIMAGE_WRITE: u32 = 6;
pub const MIPS_EBADF:u32  = 9;

trait PreimageOracle {
    fn hint(&self, v: &[u8]);
    fn get_preimage(&self, k: [u8; 32]) -> Vec<u8>;
}

struct State {
    memory: Memory,

    preimage_key: [u8; 32],
    preimage_offset: u32,

    /// the 32 general purpose registers of MIPS.
    registers: [u32; 32],
    /// the pc register stores the current execution instruction address.
    pc: u32,
    /// the next pc stores the next execution instruction address.
    next_pc: u32,
    /// the hi register stores the multiplier/divider result high(remainder) part.
    hi: u32,
    /// the low register stores the multiplier/divider result low(quotient) part.
    lo: u32,

    /// heap handles the mmap syscall.
    heap: u32,
    /// step tracks the total step has been executed.
    step: u64,

    exited: bool,
    exit_code: u8,
}

pub struct InstrumentedState {
    /// state stores the state of the MIPS emulator
    state: State,

    /// writer for stdout
    stdout_writer: Box<dyn Write>,
    /// writer for stderr
    stderr_writer: Box<dyn Write>,

    /// track the memory address last time accessed.
    last_mem_access: u32,
    /// indicates whether enable memory proof.
    mem_proof_enabled: bool,
    /// merkle proof for memory, depth is 28.
    // todo: not sure the poseidon hash length, maybe not 32 bytes.
    mem_proof: [u8; 28*32],

    preimage_oracle: Box<dyn PreimageOracle>,

    last_preimage: Vec<u8>,
    last_preimage_key: [u8; 32],
    last_preimage_offset: u32,
}

impl InstrumentedState {
    fn track_memory_access(&mut self, addr: u32) {
        if self.mem_proof_enabled && self.last_mem_access != addr {
            panic!("unexpected different memory access at {:x?}, \
            already have access at {:x?} buffered", addr, self.last_mem_access);
        }
        self.last_mem_access = addr;
        self.mem_proof = self.state.memory.merkle_proof(addr);
    }

    // (data, data_len) = self.read_preimage(self.state.preimage_key, self.state.preimage_offset)
    pub fn read_preimage(&mut self, key: [u8; 32], offset: u32) -> ([u8; 32], u32) {
        if key != self.last_preimage_key {
            self.last_preimage_key = key;
            let data = self.preimage_oracle.get_preimage(key);
            // add the length prefix
            let mut preimage = Vec::new();
            preimage.extend(data.len().to_be_bytes());
            preimage.extend(data);
            self.last_preimage = preimage;
        }
        self.last_preimage_offset = offset;

        let mut data = [0; 32];
        let bytes_to_copy = &self.last_preimage[(offset as usize)..];
        let copy_size = bytes_to_copy.len().min(data.len());

        data[..copy_size].copy_from_slice(bytes_to_copy);
        return (data, copy_size as u32);
    }

    fn handle_syscall(&mut self) -> Result<(), String> {
        let syscall_num = self.state.registers[2]; // v0
        let mut v0 = 0u32;
        let mut v1 = 0u32;

        let mut a0 = self.state.registers[4];
        let mut a1 = self.state.registers[5];
        let mut a2 = self.state.registers[6];

        match syscall_num {
            4090 => { // mmap
                // args: a0 = heap/hint, indicates mmap heap or hint. a1 = size
                let mut size = a1;
                if size&(PAGE_ADDR_MASK as u32) != 0 {
                    // adjust size to align with page size
                    size += PAGE_SIZE as u32 - (size & (PAGE_ADDR_MASK as u32));
                }
                if a0 == 0 {
                    v0 = self.state.heap;
                    self.state.heap += size;
                    debug!("mmap heap {:x?} size {:x?}", v0, size);
                } else {
                    v0 = a0;
                    debug!("mmap hint {:x?} size {:x?}", v0, size);
                }
            }
            4045 => { // brk
                v0 = 0x40000000;
            }
            4120 => { // clone
                v0 = 1;
            }
            4246 => { // exit group
                self.state.exited = true;
                self.state.exit_code = a0 as u8;
                return Ok(());
            }
            4003 => { // read
                // args: a0 = fd, a1 = addr, a2 = count
                // returns: v0 = read, v1 = err code
                match a0 {
                    FD_STDIN => {
                        // leave v0 and v1 zero: read nothing, no error
                    }
                    FD_PREIMAGE_READ => { // pre-image oracle
                        let addr = a1 & 0xFFffFFfc; // align memory
                        self.track_memory_access(addr);
                        let mem = self.state.memory.get_memory(addr);
                        let (data, mut data_len) =
                            self.read_preimage(self.state.preimage_key, self.state.preimage_offset);
                        let alignment = a1 & 3;
                        let space = 4 - alignment;
                        data_len = min(min(data_len, space), a2);

                        let mut out_mem = mem.to_be_bytes().clone();
                        out_mem[(alignment as usize)..].copy_from_slice(&data[..(data_len as usize)]);
                        self.state.memory.set_memory(addr, u32::from_be_bytes(out_mem));
                        self.state.preimage_offset += data_len;
                        v0 = data_len;
                    }
                    FD_HINT_READ => { // hint response
                        // don't actually read into memory,
                        // just say we read it all, we ignore the result anyway
                        v0 = a2;
                    }
                    _ => {
                        v0 = 0xFFffFFff;
                        v1 = MIPS_EBADF;
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }
}