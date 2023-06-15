#[derive(Default)]
pub struct StepWitness {
    // encoded state witness
    pub state: Vec<u8>,
    pub mem_proof: Vec<u8>,

    pub preimage_key: [u8; 32], // zeroed when no pre-image is accessed
    pub preimage_value: Vec<u8>, // including the 8-byte length prefix
    pub preimage_offset: u32,
}
