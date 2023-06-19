#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::iter::zip;
    use std::path::PathBuf;
    use elf::ElfBytes;
    use elf::endian::AnyEndian;
    use sha3::{Digest, Keccak256};
    use sha3::digest::{FixedOutputReset, Reset};
    use crate::pre_image::{Keccak256Key, Key, LocalIndexKey, PreimageOracle};
    use crate::state::{InstrumentedState, State};

    const END_ADDR: u32 = 0xa7ef00d0;

    struct TestOracle {
        images: HashMap<[u8; 32], Vec<u8>>,
        pre_hash: [u8; 32],
        diff_hash: [u8; 32],
        diff: [u8; 64],
        s: u64,
        a: u64,
        b: u64,
    }

    impl Default for TestOracle {
        fn default() -> Self {
            Self {
                images: HashMap::default(),
                pre_hash: [0; 32],
                diff_hash: [0; 32],
                diff: [0; 64],
                s: 0,
                a: 0,
                b: 0,
            }
        }
    }

    fn encode_u64(x: u64)-> Vec<u8> {
        return x.to_be_bytes().to_vec();
    }

    impl PreimageOracle for TestOracle {
        fn hint(&mut self, v: &[u8]) {
            let v = String::from_utf8(v.to_vec()).expect("call hint with invalid value");
            let parts = v.split_whitespace();

            let mut cmd: &str = Default::default();
            let mut hash: &str = Default::default();

            let mut count = 0;
            parts.for_each(|part|{
                if count == 0 {
                    cmd = part;
                } else if count == 1 {
                    hash = part;
                }
                count+=1
            });

            if count != 2 || hash.len() != 64 {
                panic!("call hint with invalid value {:?}", v);
            }
            let hash = hex::decode(hash).expect("call hint will invalid hash");

            match cmd {
                "fetch-state" => {
                    let mut same = true;
                    for (a, b) in zip(hash, self.pre_hash) {
                        if a != b {
                            same = false;
                            break;
                        }
                    }
                    if same == false {
                        panic!("expecting request hint for pre-state pre-image");
                    }
                    self.images.insert(Keccak256Key(self.pre_hash).preimage_key(), encode_u64(self.s));
                }
                "fetch-diff" => {
                    let mut same = true;
                    for (a, b) in zip(hash, self.diff_hash) {
                        if a != b {
                            same = false;
                            break;
                        }
                    }
                    if same == false {
                        panic!("expecting request hint for diff pre-images");
                    }

                    let mut hasher = Keccak256::default();
                    hasher.update(encode_u64(self.a).as_slice());
                    let encode_a_hash: [u8; 32] = hasher.finalize_fixed_reset().try_into().unwrap();
                    hasher.update(encode_u64(self.b).as_slice());
                    let encode_b_hash: [u8; 32] = hasher.finalize_fixed_reset().try_into().unwrap();

                    self.images.insert(Keccak256Key(self.diff_hash).preimage_key(), self.diff.to_vec());
                    self.images.insert(Keccak256Key(encode_a_hash).preimage_key(), encode_u64(self.a));
                    self.images.insert(Keccak256Key(encode_b_hash).preimage_key(), encode_u64(self.b));
                }
                _ => {
                    panic!("unexpected hint {}", cmd);
                }
            }
        }

        fn get_preimage(&self, k: [u8; 32]) -> Vec<u8> {
            match self.images.get(&k) {
                None => {
                    panic!("missing pre-image {:?}", k);
                },
                Some(preimage) => {
                    preimage.to_vec()
                }
            }
        }
    }

    fn claim_test_oracle() -> TestOracle {
        let s: u64 = 1000;
        let a: u64 = 3;
        let b: u64 = 4;

        let mut diff: Vec<u8> = Vec::<u8>::new();

        let mut hasher = Keccak256::default();
        hasher.update(encode_u64(a).as_slice());

        let hash: [u8; 32] = hasher.finalize_fixed_reset().try_into().unwrap();
        diff.extend(hash);
        Reset::reset(&mut hasher);

        hasher.update(encode_u64(b).as_slice());
        let hash: [u8; 32] = hasher.finalize_fixed_reset().try_into().unwrap();
        diff.extend(hash);
        Reset::reset(&mut hasher);

        hasher.update(encode_u64(s).as_slice());
        let pre_hash: [u8; 32] = hasher.finalize_fixed_reset().try_into().unwrap();
        Reset::reset(&mut hasher);

        hasher.update(diff.as_slice());
        let diff_hash: [u8; 32] = hasher.finalize_fixed_reset().try_into().unwrap();

        let diff: [u8; 64] = diff.try_into().unwrap();

        let mut oracle = TestOracle {
            images: Default::default(),
            pre_hash,
            diff_hash,
            diff,
            s,
            a,
            b,
        };

        oracle.images.insert(LocalIndexKey(0).preimage_key(), pre_hash.to_vec());
        oracle.images.insert(LocalIndexKey(1).preimage_key(), diff_hash.to_vec());
        oracle.images.insert(LocalIndexKey(2).preimage_key(), encode_u64(s*a+b));

        oracle
    }

    fn execute_open_mips(path: PathBuf) {
        if path.ends_with("oracle.bin") {
            println!("oracle test needs to be updated to use syscall pre-image oracle");
            return;
        }
        let data = fs::read(path).expect("could not read file");
        let data: Box<&[u8]> = Box::new(data.as_slice());

        let mut state = State::new();
        state.memory.set_memory_range(0, data).expect("set memory range failed");
        state.registers[31] = END_ADDR;

        let preimage_oracle = Box::new(TestOracle::default());
        let mut instrumented_state = InstrumentedState::new(state, preimage_oracle);

        for _ in 0..1000 {
            if instrumented_state.state.pc == END_ADDR {
                break;
            }
            instrumented_state.step(true);
        }
    }

    #[test]
    fn test_execute_open_mips() {
        for file_name in fs::read_dir("./open_mips_tests/test/bin/").unwrap() {
            execute_open_mips(file_name.unwrap().path());
        }
    }

    #[test]
    fn test_execute_hello() {
        let path = PathBuf::from("./example/bin/hello.elf");
        let data = fs::read(path).expect("could not read file");
        let file = ElfBytes::<AnyEndian>::minimal_parse(
            data.as_slice()
        ).expect("opening elf file failed");
        let mut state = State::load_elf(&file);

        state.patch_go(&file);
        state.patch_stack();

        let preimage_oracle = Box::new(TestOracle::default());
        let mut instrumented_state = InstrumentedState::new(state, preimage_oracle);

        for _ in 0..400000 {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step(true);
        }
    }

    #[test]
    fn test_execute_claim() {
        let path = PathBuf::from("./example/bin/claim.elf");
        let data = fs::read(path).expect("could not read file");
        let file = ElfBytes::<AnyEndian>::minimal_parse(
            data.as_slice()
        ).expect("opening elf file failed");
        let mut state = State::load_elf(&file);

        state.patch_go(&file);
        state.patch_stack();

        let preimage_oracle = Box::new(claim_test_oracle());
        let mut instrumented_state = InstrumentedState::new(state, preimage_oracle);

        for _ in 0..2000_000 {
            if instrumented_state.state.exited {
                break;
            }
            instrumented_state.step(true);
        }
    }
}
