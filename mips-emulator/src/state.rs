use std::io::{Read, stderr, stdout, Write};
use crate::memory::Memory;
use crate::page::{PAGE_ADDR_MASK, PAGE_SIZE};
use log::{debug, warn};
use std::cmp::min;
use std::fmt::{Display, Formatter};
use elf::abi::PT_LOAD;
use elf::endian::AnyEndian;
use rand::{Rng, thread_rng};
use crate::pre_image::PreimageOracle;
use crate::witness::{Program, ProgramSegment, StepWitness};

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_HINT_READ: u32 = 3;
pub const FD_HINT_WRITE: u32 = 4;
pub const FD_PREIMAGE_READ: u32 = 5;
pub const FD_PREIMAGE_WRITE: u32 = 6;
pub const MIPS_EBADF:u32  = 9;

pub struct State {
    pub memory: Box<Memory>,

    preimage_key: [u8; 32],
    preimage_offset: u32,

    /// the 32 general purpose registers of MIPS.
    pub registers: [u32; 32],
    /// the pc register stores the current execution instruction address.
    pub pc: u32,
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

    pub exited: bool,
    exit_code: u8,

    // last_hint is optional metadata, and not part of the VM state itself.
    // It is used to remember the last pre-image hint,
    // so a VM can start from any state without fetching prior pre-images,
    // and instead just repeat the last hint on setup,
    // to make sure pre-image requests can be served.
    // The first 4 bytes are a uin32 length prefix.
    // Warning: the hint MAY NOT BE COMPLETE. I.e. this is buffered,
    // and should only be read when len(LastHint) > 4 && uint32(LastHint[:4]) >= len(LastHint[4:])
    last_hint: Vec<u8>,
}

impl Display for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "State {{ \n pc: 0x{:x}, next_pc: 0x{:x}, hi: {}, lo: {}, heap: 0x{:x}, step: {}, exited: {}, \
            \n registers: {:?} \
            \n memory: {} \n}}",
            self.pc, self.next_pc, self.hi, self.lo, self.heap, self.step, self.exited, self.registers, self.memory.usage()
        )
    }
}

impl State {
    pub fn new() -> Box<Self> {
        Box::new(Self{
            memory: Box::new(Memory::new()),
            preimage_key: Default::default(),
            preimage_offset: 0,
            registers: Default::default(),
            pc: 0,
            next_pc: 4,
            hi: 0,
            lo: 0,
            heap: 0,
            step: 0,
            exited: false,
            exit_code: 0,
            last_hint: Default::default(),
        })
    }

    pub fn encode_witness(&mut self) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        let mem_root = self.memory.merkle_root();
        out.extend(mem_root);
        out.extend(self.preimage_key.clone());
        out.extend(self.preimage_offset.to_be_bytes());
        out.extend(self.pc.to_be_bytes());
        out.extend(self.next_pc.to_be_bytes());
        out.extend(self.lo.to_be_bytes());
        out.extend(self.hi.to_be_bytes());
        out.extend(self.heap.to_be_bytes());
        out.push(self.exit_code);
        if self.exited {
            out.push(1);
        } else {
            out.push(0);
        }
        out.extend(self.step.to_be_bytes());
        for register in self.registers {
            out.extend(register.to_be_bytes());
        }
        out
    }

    pub fn load_elf(f: &elf::ElfBytes<AnyEndian>) -> (Box<Self>, Box<Program>) {
        let mut s = Box::new(Self {
            memory: Box::new(Memory::new()),
            registers: Default::default(),

            preimage_key: Default::default(),
            preimage_offset: 0,

            pc: f.ehdr.e_entry as u32,
            next_pc: f.ehdr.e_entry as u32 + 4,

            hi: 0,
            lo: 0,
            heap: 0x20000000,
            step: 0,
            exited: false,
            exit_code: 0,
            last_hint: Default::default(),
        });

        let mut program = Box::from(Program::new());

        let segments = f.segments()
            .expect("invalid ELF cause failed to parse segments.");
        for segment in segments {
            if segment.p_type == 0x70000003 {
                continue;
            }

            let r = f.segment_data(&segment).expect("failed to parse segment data");
            let mut r = Vec::from(r);

            if segment.p_filesz != segment.p_memsz {
                if segment.p_type == PT_LOAD {
                    if segment.p_filesz < segment.p_memsz {
                        let diff = (segment.p_memsz-segment.p_filesz) as usize;
                        r.extend_from_slice(vec![0u8; diff].as_slice());
                    } else {
                        panic!("invalid PT_LOAD program segment, file size ({}) > mem size ({})",
                               segment.p_filesz, segment.p_memsz);
                    }
                } else {
                    panic!("has different file size ({}) than mem size ({}): filling for non PT_LOAD segments is not supported",
                           segment.p_filesz, segment.p_memsz);
                }
            }

            if segment.p_vaddr + segment.p_memsz >= 1u64 << 32 {
                panic!("program %d out of 32-bit mem range: {:x} -{:x} (size: {:x})",
                       segment.p_vaddr, segment.p_memsz, segment.p_memsz);
            }

            let n = r.len();
            let r: Box<&[u8]>= Box::new(r.as_slice());
            s.memory.set_memory_range(segment.p_vaddr as u32, r).expect(
                "failed to set memory range"
            );

            if n != 0 {
                program.segments.push(
                    ProgramSegment {
                        start_addr: segment.p_vaddr as u32,
                        segment_size: n as u32,
                        instructions: vec![],
                    }
                )
            }
        }
        (s, program)
    }

    pub fn patch_go(&mut self, f: &elf::ElfBytes<AnyEndian>) {
        let symbols = f.symbol_table()
            .expect("failed to read symbols table, cannot patch program")
            .expect("failed to parse symbols table, cannot patch program");

        for symbol in symbols.0 {
            match symbols.1.get(symbol.st_name as usize) {
                Ok(name) => {
                    match name {
                        "runtime.gcenable" | "runtime.init.5" | "runtime.main.func1" |
                        "runtime.deductSweepCredit" | "runtime.(*gcControllerState).commit" |
                        "github.com/prometheus/client_golang/prometheus.init" |
                        "github.com/prometheus/client_golang/prometheus.init.0" |
                        "github.com/prometheus/procfs.init" |
                        "github.com/prometheus/common/model.init" |
                        "github.com/prometheus/client_model/go.init" |
                        "github.com/prometheus/client_model/go.init.0" |
                        "github.com/prometheus/client_model/go.init.1" |
                        "flag.init" |
                        "runtime.check" => {
                            let r:Vec<u8> = vec![0x03, 0xe0, 0x00, 0x08, 0, 0, 0, 0];
                            let r = Box::new(r.as_slice());
                            self.memory.set_memory_range(symbol.st_value as u32, r)
                                .expect("set memory range failed");
                        }
                        "runtime.MemProfileRate" => {
                            let r:Vec<u8> = vec![0, 0, 0, 0];
                            let r = Box::new(r.as_slice());
                            self.memory.set_memory_range(symbol.st_value as u32, r)
                                .expect("set memory range failed");
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    warn!("parse symbol failed, {}", e);
                    continue;
                }
            }
        }
    }

    pub fn patch_stack(&mut self) {
        // setup stack pointer
        let sp: u32 = 0x7fFFd000;

        // allocate 1 page for the initial stack data, and 16kb = 4 pages for the stack to grow
        let r: Vec<u8> = vec![0; 5 * PAGE_SIZE];
        let r: Box<&[u8]> = Box::new(r.as_slice());

        let addr = sp - 4 * PAGE_SIZE as u32;
        self.memory.set_memory_range(addr, r)
            .expect("failed to set memory range");

        self.registers[29] = sp;

        let mut store_mem = |addr: u32, v: u32| {
            let mut dat = [0u8; 4];
            dat.copy_from_slice(&v.to_be_bytes());
            let r = Box::new(dat.as_slice());
            self.memory.set_memory_range(addr, r)
                .expect("failed to set memory range");
        };

        // init argc,  argv, aux on stack
        store_mem(sp+4*1, 0x42); // argc = 0 (argument count)
        store_mem(sp+4*2, 0x35); // argv[n] = 0 (terminating argv)
        store_mem(sp+4*3, 0x00); // envp[term] = 0 (no env vars)
        store_mem(sp+4*4, 0x06); // auxv[0] = _AT_PAGESZ = 6 (key)
        store_mem(sp+4*5, 0x1000); // auxv[1] = page size of 4 KiB (value) - (== minPhysPageSize)
        store_mem(sp+4*6, 0x1A); // auxv[2] = AT_RANDOM
        store_mem(sp+4*7, sp+4*9); // auxv[3] = address of 16 bytes containing random value
        store_mem(sp+4*8, 0); // auxv[term] = 0

        let mut rng = thread_rng();
        let r: [u8; 16] = rng.gen();
        let r: Box<&[u8]> = Box::new(r.as_slice());
        self.memory.set_memory_range(sp+4*9, r)
            .expect("failed to set memory range");
    }
}

pub struct InstrumentedState {
    /// state stores the state of the MIPS emulator
    pub state: Box<State>,

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

impl Display for InstrumentedState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "state: {}, last_mem_access: {}, proof_enabled: {}",
            self.state, self.last_mem_access, self.mem_proof_enabled
        )
    }
}

impl InstrumentedState {
    pub fn new(
        state: Box<State>,
        preimage_oracle: Box<dyn PreimageOracle>
    ) -> Box<Self> {
        let is = Box::new(Self{
            state,
            stdout_writer: Box::new(stdout()),
            stderr_writer: Box::new(stderr()),
            last_mem_access: !(0u32),
            mem_proof_enabled: true,
            mem_proof: [0; 28*32],
            preimage_oracle,
            last_preimage: Vec::<u8>::new(),
            last_preimage_key: [0; 32],
            last_preimage_offset: 0,
        });
        is
    }

    fn track_memory_access(&mut self, addr: u32) {
        if self.mem_proof_enabled && self.last_mem_access != addr {
            if self.last_mem_access != !(0u32) {
                panic!("unexpected different memory access at {:x?}, \
                    already have access at {:x?} buffered", addr, self.last_mem_access);
            }
        }
        self.last_mem_access = addr;
        self.mem_proof = self.state.memory.merkle_proof(addr);
    }

    // (data, data_len) = self.read_preimage(self.state.preimage_key, self.state.preimage_offset)
    fn read_preimage(&mut self, key: [u8; 32], offset: u32) -> ([u8; 32], u32) {
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
        let bytes_to_copy = &self.last_preimage[(offset as usize)..]; // length: 32 - offset
        let copy_size = bytes_to_copy.len().min(data.len()); // length: 32 - offset

        data[..copy_size].copy_from_slice(&bytes_to_copy[..copy_size]); // equal length
        return (data, copy_size as u32);
    }

    fn handle_syscall(&mut self) {
        let syscall_num = self.state.registers[2]; // v0
        let mut v0 = 0u32;
        let mut v1 = 0u32;

        let a0 = self.state.registers[4];
        let a1 = self.state.registers[5];
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
                return;
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
                        data_len = min(min(data_len, space), a2); // at most 4

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
            4004 => { // write
                // args: a0 = fd, a1 = addr, a2 = count
                // returns: v0 = written, v1 = err code
                match a0 {
                    FD_STDOUT => {
                        self.state.memory.read_memory_range(a1, a2);
                        match std::io::copy(self.state.memory.as_mut(), self.stdout_writer.as_mut()) {
                            Err(e) => {
                                panic!("read range from memory failed {}", e);
                            }
                            Ok(_) => {}
                        }
                        v0 = a2;
                    }
                    FD_STDERR => {
                        self.state.memory.read_memory_range(a1, a2);
                        match std::io::copy(self.state.memory.as_mut(), self.stderr_writer.as_mut()) {
                            Err(e) => {
                                panic!("read range from memory failed {}", e);
                            }
                            Ok(_) => {}
                        }
                        v0 = a2;
                    }
                    FD_HINT_WRITE => {
                        self.state.memory.read_memory_range(a1, a2);
                        let mut hint_data = Vec::<u8>::new();
                        self.state.memory.read_to_end(&mut hint_data).unwrap();
                        self.state.last_hint.extend(&hint_data);
                        while self.state.last_hint.len() > 4 {
                            // process while there is enough data to check if there are any hints.
                            let mut hint_len_bytes = [0u8; 4];
                            hint_len_bytes.copy_from_slice(&self.state.last_hint[..4]);
                            let hint_len = u32::from_be_bytes(hint_len_bytes) as usize;
                            if hint_len >= self.state.last_hint[4..].len() {
                                let mut hint = Vec::<u8>::new();
                                self.state.last_hint[4..(4 + hint_len)].clone_into(&mut hint);
                                self.state.last_hint = self.state.last_hint.split_off(4+hint_len);
                                self.preimage_oracle.hint(hint.as_slice());
                            }
                        }
                        v0 = a2;
                    }
                    FD_PREIMAGE_WRITE => {
                        let addr = a1 & 0xFFffFFfc;
                        self.track_memory_access(addr);
                        let out_mem = self.state.memory.get_memory(addr);

                        let alignment = a1 & 3;
                        let space = 4 - alignment;
                        a2 = min(a2, space); // at most write to 4 bytes

                        let mut key = [0; 32];
                        for i in (a2 as usize)..32 {
                            key[i-(a2 as usize)] = self.state.preimage_key[i];
                        }
                        let out_mem_be = out_mem.to_be_bytes();
                        for i in (32-a2 as usize)..32 {
                            key[i] = out_mem_be[i+(a2 as usize)-32];
                        }

                        self.state.preimage_key = key;
                        self.state.preimage_offset = 0;
                        v0 = a2;
                    }
                    _ => {
                        v0 = 0xFFffFFff;
                        v1 = MIPS_EBADF;
                    }
                }
            }
            4055 => { // fcntl
                // args: a0 = fd, a1 = cmd
                if a1 == 3 { // F_GETFL: get file descriptor flags
                    match a0 {
                        FD_STDIN | FD_PREIMAGE_READ | FD_HINT_READ => {
                            v0 = 0 // O_RDONLY
                        }
                        FD_STDOUT | FD_STDERR | FD_PREIMAGE_WRITE | FD_HINT_WRITE => {
                            v0 = 1 // O_WRONLY
                        }
                        _ => {
                            v0 = 0xFFffFFff;
                            v1 = MIPS_EBADF;
                        }
                    }
                } else {
                    v0 = 0xFFffFFff;
                    v1 = MIPS_EBADF;
                }
            }
            _ => {}
        }

        self.state.registers[2] = v0;
        self.state.registers[7] = v1;

        self.state.pc = self.state.next_pc;
        self.state.next_pc = self.state.next_pc + 4;
    }

    fn handle_branch(&mut self, opcode: u32, insn: u32, rt_reg: u32, rs: u32) {
        let should_branch = match opcode {
            4 | 5 => { // beq/bne
                let rt = self.state.registers[rt_reg as usize];
                (rs == rt && opcode == 4) || (rs != rt && opcode == 5)
            }
            6 => { // blez
                (rs as i32) <= 0
            }
            7 => { // bgtz
                (rs as i32) > 0
            }
            1 => { // reqimm
                let rtv = (insn >> 16) & 0x1F;
                if rtv == 0 { // bltz
                    (rs as i32) < 0
                } else if rtv == 1 { // 1 -> bgez
                    (rs as i32) >= 0
                } else {
                    false
                }
            }
            _ => {
                panic!("invalid branch opcode {}", opcode);
            }
        };

        let prev_pc = self.state.pc;
        self.state.pc = self.state.next_pc; // execute the delay slot first
        if should_branch  {
            // then continue with the instruction the branch jumps to.
            self.state.next_pc = prev_pc + 4 + (sign_extension(insn&0xFFFF, 16) << 2);
        } else {
            self.state.next_pc = self.state.next_pc + 4;
        }
    }

    fn handle_jump(&mut self, link_reg: u32, dest: u32) {
        let prev_pc = self.state.pc;
        self.state.pc = self.state.next_pc;
        self.state.next_pc = dest;

        if link_reg != 0 {
            // set the link-register to the instr after the delay slot instruction.
            self.state.registers[link_reg as usize] = prev_pc + 8;
        }
    }

    fn handle_hilo(&mut self, fun: u32, rs: u32, rt: u32, store_reg: u32) {
        let mut val = 0u32;
        match fun {
            0x10 => { // mfhi
                val = self.state.hi;
            }
            0x11 => { // mthi
                self.state.hi = rs;
            }
            0x12 => { // mflo
                val = self.state.lo;
            }
            0x13 => { // mtlo
                self.state.lo = rs;
            }
            0x18 => { // mult
                let acc = (rs as i64 * rt as i64) as u64;
                self.state.hi = (acc >> 32) as u32;
                self.state.lo = acc as u32;
            }
            0x19 => { // mulu
                let acc = rs as u64 * rt as u64;
                self.state.hi = (acc >> 32) as u32;
                self.state.lo = acc as u32;
            }
            0x1a => { // div
                self.state.hi = ((rs as i32) % (rt as i32)) as u32;
                self.state.lo = ((rs as i32) / (rt as i32)) as u32;
            }
            0x1b => { // divu
                self.state.hi = rs % rt;
                self.state.lo = rs / rt;
            }
            n => {
                panic!("invalid fun when process hi lo, fun: {}", n);
            }
        }

        if store_reg != 0 {
            self.state.registers[store_reg as usize] = val;
        }

        self.state.pc = self.state.next_pc;
        self.state.next_pc = self.state.next_pc + 4;
    }

    fn handle_rd(&mut self, store_reg: u32, val: u32, conditional: bool) {
        if store_reg >=32 {
            panic!("invalid register");
        }
        if store_reg != 0 && conditional {
            self.state.registers[store_reg as usize] = val;
        }

        self.state.pc = self.state.next_pc;
        self.state.next_pc = self.state.next_pc + 4;
    }

    fn mips_step(&mut self) {
        if self.state.exited {
            return;
        }

        self.state.step += 1;

        // fetch instruction
        let insn = self.state.memory.get_memory(self.state.pc);
        let opcode = insn >> 26; // 6-bits

        // j-type j/jal
        if opcode == 2 || opcode == 3 {
            let link_reg = match opcode {
                3 => { 31 }
                _ => { 0 }
            };

            return self.handle_jump(link_reg, sign_extension(insn&0x03ffFFff, 26)<<2);
        }

        // fetch register
        let mut rt = 0u32;
        let rt_reg = (insn >> 16) & 0x1f;

        // R-type or I-type (stores rt)
        let mut rs = self.state.registers[((insn >> 21) & 0x1f) as usize];
        let mut rd_reg = rt_reg;
        if opcode == 0 || opcode == 0x1c {
            // R-type (stores rd)
            rt = self.state.registers[rt_reg as usize];
            rd_reg = (insn >> 11) & 0x1f;
        } else if opcode < 0x20 {
            // rt is SignExtImm
            // don't sign extend for andi, ori, xori
            if opcode == 0xC || opcode == 0xD || opcode == 0xE {
                // ZeroExtImm
                rt = insn & 0xFFFF;
            } else {
                rt = sign_extension(insn&0xffFF, 16);
            }
        } else if opcode >= 0x28 || opcode == 0x22 || opcode == 0x26 {
            // store rt value with store
            rt = self.state.registers[rt_reg as usize];

            // store actual rt with lwl and lwr
            rd_reg = rt_reg;
        }

        if (opcode >= 4 && opcode < 8) || opcode == 1 {
            return self.handle_branch(opcode, insn, rt_reg, rs);
        }

        let mut store_addr: u32 = 0xffFFffFF;
        // memory fetch (all I-type)
        // we do the load for stores also
        let mut mem: u32 = 0;
        if opcode >= 0x20 {
            // M[R[rs]+SignExtImm]
            rs += sign_extension(insn&0xffFF, 16);
            let addr = rs & 0xFFffFFfc;
            self.track_memory_access(addr);
            mem = self.state.memory.get_memory(addr);
            if opcode >= 0x28 && opcode != 0x30 {
                // store
                store_addr = addr;
                // store opcodes don't write back to a register
                rd_reg = 0;
            }
        }

        // ALU
        let val = self.execute(insn, rs, rt, mem);

        let fun = insn & 0x3f; // 6-bits
        if opcode == 0 && fun >= 8 && fun < 0x1c {
            if fun == 8 || fun ==9 {
                let link_reg = match fun {
                    9=> {rd_reg},
                    _=> {0}
                };
                return self.handle_jump(link_reg, rs);
            }

            if fun == 0xa {
                return self.handle_rd(rd_reg, rs, rt == 0);
            }
            if fun == 0xb {
                return self.handle_rd(rd_reg, rs, rt != 0);
            }

            // syscall (can read/write)
            if fun == 0xc {
                return self.handle_syscall();
            }

            // lo and hi registers
            // can write back
            if fun >= 0x10 && fun < 0x1c {
                return self.handle_hilo(fun, rs, rt, rd_reg);
            }
        }

        // stupid sc, write a 1 to rt
        if opcode == 0x38 && rt_reg != 0 {
            self.state.registers[rt_reg as usize] = 1;
        }

        // write memory
        if store_addr != 0xffFFffFF {
            self.track_memory_access(store_addr);
            self.state.memory.set_memory(store_addr, val);
        }

        // write back the value to the destination register
        return self.handle_rd(rd_reg, val, true);
    }

    fn execute(&mut self, insn: u32, mut rs: u32, rt: u32, mem: u32) -> u32 {
        // implement alu
        let mut opcode = insn >> 26;
        let mut fun = insn & 0x3F;

        if opcode < 0x20 {
            // transform ArithLogI
            if opcode >= 8 && opcode < 0xf {
                match opcode {
                    8 => {
                        fun = 0x20; // addi
                    }
                    9=> {
                        fun = 0x21; // addiu
                    }
                    0xa => {
                        fun = 0x2a; // slti
                    }
                    0xb => {
                        fun = 0x2b; // sltiu
                    }
                    0xc => {
                        fun = 0x24; // andi
                    }
                    0xd => {
                        fun = 0x25; // ori
                    }
                    0xe => {
                        fun = 0x26; // xori
                    }
                    _ => {}
                }
                opcode = 0;
            }

            // 0 is opcode SPECIAL
            if opcode == 0 {
                let shamt = (insn >> 6) & 0x1f;
                if fun < 0x20 {
                    if fun >= 0x08 {
                        return rs; // jr/jalr/div + others
                    } else if fun == 0x00 {
                        return rt << shamt; // sll
                    } else if fun == 0x02 {
                        return rt >> shamt; // srl
                    } else if fun == 0x03 {
                        return sign_extension(rt >> shamt, 32-shamt); // sra
                    } else if fun == 0x04 {
                        return rt << (rs & 0x1f); // sllv
                    } else if fun == 0x06 {
                        return rt >> (rs & 0x1f); // srlv
                    } else if fun == 0x07 {
                        return sign_extension(rt>>rs, 32-rs); // srav
                    }
                }

                // 0x10 - 0x13 = mfhi, mthi, mflo, mtlo
                // R-type (ArithLog)
                match fun {
                    0x20 | 0x21 => {
                        return rs + rt; // add or addu
                    }
                    0x22 | 0x23 => {
                        return rs - rt; // sub or subu
                    }
                    0x24 => {
                        return rs & rt; // and
                    }
                    0x25 => {
                        return rs | rt; // or
                    }
                    0x26 => {
                        return rs ^ rt; // xor
                    }
                    0x27 => {
                        return !(rs | rt); // nor
                    }
                    0x2a => {
                        return if (rs as i32) < (rt as i32) {
                            1 // slt
                        } else {
                            0
                        }
                    }
                    0x2b => {
                        return if rs < rt {
                            1 // sltu
                        } else {
                            0
                        }
                    }
                    _ => {}
                }
            } else if opcode == 0xf {
                return rt << 16; // lui
            } else if opcode == 0x1c { // SPECIAL2
                if fun == 2 { // mul
                    return ((rs as i32) * (rt as i32)) as u32;
                }
                if fun == 0x20 || fun == 0x21 { // clo
                    if fun == 0x20 {
                        rs = !rs;
                    }
                    let mut i = 0;
                    while rs & 0x80000000 != 0 {
                        rs <<= 1;
                        i += 1;
                    }
                    return i;
                }
            }
        } else if opcode < 0x28 {
            match opcode {
                0x20 => { // lb
                    return sign_extension((mem>>(24-(rs&3)*8))&0xff, 8);
                }
                0x21 => { // lh
                    return sign_extension((mem>>(16-(rs&2)*8))&0xffff, 16);
                }
                0x22 => { // lwl
                    let val = mem << ((rs & 3) * 8);
                    let mask = 0xffFFffFFu32 << ((rs & 3) * 8);
                    return (rt & (!mask)) | val;
                }
                0x23 => { // lw
                    return mem;
                }
                0x24 => { // lbu
                    return (mem >> (24 - (rs & 3)*8)) & 0xff;
                }
                0x25 => { // lhu
                    return (mem >> (16 - (rs & 2)*8)) & 0xffff;
                }
                0x26 => { // lwr
                    let val = mem >> (24 - (rs&3)*8);
                    let mask = 0xffFFffFFu32 >> (24 - (rs&3)*8);
                    return (rt & (!mask)) | val;
                }
                _ => {}
            }
        } else if opcode == 0x28 { // sb
            let val = (rt & 0xff) << (24 - (rs&3)*8);
            let mask = 0xffFFffFFu32 ^ (0xff<<(24-(rs&3)*8));
            return (mem & mask) | val;
        } else if opcode == 0x29 { // sh
            let val = (rt & 0xffff) << (16 - (rs&2)*8);
            let mask = 0xffFFffFFu32 ^ (0xffff<<(16-(rs&2)*8));
            return (mem & mask) | val;
        } else if opcode == 0x2a { // swl
            let val = rt >> ((rs & 3) * 8);
            let mask = 0xffFFffFFu32 >> ((rs & 3) * 8);
            return (mem & (!mask)) | val;
        } else if opcode == 0x2b { // sw
            return rt;
        } else if opcode == 0x2e { // swr
            let val = rt << (24 - (rs & 3) *8 );
            let mask = 0xffFFffFFu32 << (24 - (rs & 3) *8 );
            return (mem & (!mask)) | val;
        } else if opcode == 0x30 { // ll
            return mem;
        } else if opcode == 0x38 { // sc
            return rt;
        }

        panic!("invalid instruction, opcode: {}", opcode);
    }

    pub fn step(&mut self, proof: bool) -> Box<StepWitness> {
        self.mem_proof_enabled = proof;
        self.last_mem_access = !(0u32);
        self.last_preimage_offset = !(0u32);

        let mut wit: Box<StepWitness> = Default::default();

        if proof {
            let insn_proof = self.state.memory.merkle_proof(self.state.pc);
            wit.state = self.state.encode_witness();
            wit.mem_proof = insn_proof.to_vec();
        }
        self.mips_step();

        if proof {
            wit.mem_proof.extend(self.mem_proof.clone());
            if self.last_preimage_offset != !(0u32) {
                wit.preimage_offset = self.last_preimage_offset;
                wit.preimage_key = self.last_preimage_key;
                wit.preimage_value.clone_from(&self.last_preimage);
            }
        }

        wit
    }
}

/// se extends the number to 32 bit with sign.
fn sign_extension(dat: u32, idx: u32) -> u32 {
    let is_signed = (dat >> (idx-1)) != 0;
    let signed = ((1u32 << (32-idx)) - 1) << idx;
    let mask = (1u32 << idx) - 1;
    if is_signed {
        dat & mask | signed
    } else {
        dat & mask
    }
}
