#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use clap::Parser;
use elf::ElfBytes;
use elf::endian::AnyEndian;
use log::info;
use crate::pre_image::PreimageOracle;
use crate::state::{InstrumentedState, State};

mod page;
mod memory;
mod state;

mod tests;
mod witness;
mod pre_image;

#[derive(Default)]
struct Oracle { }

impl PreimageOracle for Oracle {
    fn hint(&mut self, _v: &[u8]) {
        todo!()
    }

    fn get_preimage(&self, _k: [u8; 32]) -> Vec<u8> {
        todo!()
    }
}

#[derive(Parser, Debug)]
struct Args {
    // Path of the compiled MIPS binary program
    #[arg(short, long)]
    path: String,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    info!("executing {}!", args.path);

    let path = PathBuf::from(args.path);
    let data = fs::read(path).expect("could not read file");
    let file = ElfBytes::<AnyEndian>::minimal_parse(
        data.as_slice()
    ).expect("opening elf file failed");
    let mut state = State::load_elf(&file);

    state.patch_go(&file);
    state.patch_stack();

    let preimage_oracle = Box::new(Oracle::default());
    let mut instrumented_state = InstrumentedState::new(state, preimage_oracle);

    for _ in 0..400000 {
        if instrumented_state.state.exited {
            break;
        }
        instrumented_state.step(true);
    }
}
