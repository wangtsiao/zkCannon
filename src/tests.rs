#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use elf::ElfBytes;
    use elf::endian::AnyEndian;
    use crate::state::{InstrumentedState, PreimageOracle, State};

    const END_ADDR: u32 = 0xa7ef00d0;

    struct TestOracle {}

    impl PreimageOracle for TestOracle {
        fn hint(&self, _v: &[u8]) {
            todo!()
        }

        fn get_preimage(&self, _k: [u8; 32]) -> Vec<u8> {
            todo!()
        }
    }

    fn execute_open_mips(path: PathBuf) {
        println!("============= testing file {:?} =============", path);
        if path.ends_with("oracle.bin") {
            println!("oracle test needs to be updated to use syscall pre-image oracle");
            return;
        }
        let data = fs::read(path).expect("could not read file");
        let data: Box<&[u8]> = Box::new(data.as_slice());

        let mut state = State::new();
        state.memory.set_memory_range(0, data).expect("set memory range failed");
        state.registers[31] = END_ADDR;

        let preimage_oracle = Box::new(TestOracle {});
        let mut instrumented_state = InstrumentedState::new(state, preimage_oracle);

        println!("before step state: {}", instrumented_state);
        for _ in 0..1000 {
            if instrumented_state.state.pc == END_ADDR {
                break;
            }
            instrumented_state.step(true);
        }
        println!("before step state: {}", instrumented_state);
    }

    #[test]
    fn test_execute_open_mips() {
        for file_name in fs::read_dir("./open_mips_tests/test/bin/").unwrap() {
            execute_open_mips(file_name.unwrap().path());
        }
    }

    #[test]
    fn test_load_elf() {
        let path = PathBuf::from("./example/bin/hello.elf");
        let data = fs::read(path).expect("could not read file");
        let file = ElfBytes::<AnyEndian>::minimal_parse(
            data.as_slice()
        ).expect("opening elf file failed");
        let state = State::load_elf(file);

        let preimage_oracle = Box::new(TestOracle {});
        let mut instrumented_state = InstrumentedState::new(state, preimage_oracle);

        println!("before step state: {}", instrumented_state);
        for _ in 0..1000 {
            instrumented_state.step(false);
        }
        println!("before step state: {}", instrumented_state);
    }

}
