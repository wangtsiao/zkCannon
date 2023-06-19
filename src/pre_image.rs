pub trait PreimageOracle {
    fn hint(&mut self, v: &[u8]);
    fn get_preimage(&self, k: [u8; 32]) -> Vec<u8>;
}

pub trait Key {
    // preimage_key changes the Key commitment into a
    // 32-byte type-prefixed preimage key.
    fn preimage_key(&self) -> [u8; 32];
}

const LOCAL_KEY_TYPE: u8 = 1;
const KECCAK256KEY_TYPE: u8 = 2;

pub struct LocalIndexKey(pub u64);

impl Key for LocalIndexKey {
    fn preimage_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = LOCAL_KEY_TYPE;
        out[24..32].copy_from_slice(self.0.to_be_bytes().as_slice());
        out
    }
}

pub struct Keccak256Key(pub [u8;32]);

impl Key for Keccak256Key {
    fn preimage_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.as_slice());
        out[0] = KECCAK256KEY_TYPE;
        out
    }
}

pub trait Hint {
    fn hint() -> String;
}
