#![allow(dead_code)]
mod page;
mod memory;
mod state;

use page::CachedPage;
use memory::Memory;

fn main() {
    env_logger::init();

    let mut cached_page = CachedPage::new();
    let merkle_root = cached_page.merkle_root();
    cached_page.invalidate(0xFA4);
    println!("page merkle root: {:x?}", merkle_root);

    let mut memory = Memory::new();
    let merkle_root = memory.merkle_root();
    println!("memory merkle root: {:x?}", merkle_root);
    let merkle_proof = memory.merkle_proof(0xFA4);
    println!("memory merkle proof: {:x?}", merkle_proof);
}
