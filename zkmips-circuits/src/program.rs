mod chip;

use std::marker::PhantomData;
use group::{Curve, Group};

use halo2_gadgets::{
    ecc::{
        chip::{find_zs_and_us, H, NUM_WINDOWS, NUM_WINDOWS_SHORT,
               BaseFieldElem, FixedPoint, ShortScalar},
        FixedPoints,
    },
    sinsemilla::{
        HashDomains,
        CommitDomains,
        primitives as sinsemilla,
        chip::SinsemillaChip,
        SinsemillaInstructions,
    },
    utilities::{
        lookup_range_check::LookupRangeCheckConfig,
        UtilitiesInstructions,
    }
};

use halo2_proofs::{
    circuit::{Layouter, Value, AssignedCell, Chip},
    halo2curves::{
        pasta::pallas,
        ff::{PrimeFieldBits, PrimeField},
    },
    plonk::{Advice, Column, ConstraintSystem, TableColumn, Error, Fixed, Instance},
    arithmetic::CurveAffine,
};

use lazy_static::lazy_static;

use mips_emulator::witness::{
    Program,
    PERSONALIZATION,
};
use crate::program::chip::{HashRoundChip, HashRoundConfig};


/// Instructions to check the sinsemilla hash correct execution.
/// The sinsemilla hash instance is `K`-bit words.
/// The sinsemilla hash instance can process `MAX_WORDS` words.
pub trait HashRoundInstructions<
    C: CurveAffine,
    const K: usize,
    const MAX_WORDS: usize
>:
    SinsemillaInstructions<C, K, MAX_WORDS>
    + UtilitiesInstructions<C::Base>
    + Chip<C::Base>
{
    /// Compute hash for a given round. The hash accepts
    /// a chunk of data.
    #[allow(non_snake_case)]
    fn hash_round(
        &self,
        layouter: impl Layouter<C::Base>,
        Q: pallas::Affine, // todo: should be C, but error is pallas::Affine not implement C
        pre: Self::Var,
        chunks: [Value<C::Base>; 8],
    ) -> Result<Self::Var, Error>;
}


/// Gadget representing a program chunk
#[derive(Clone, Debug)]
pub struct HashChunk<
    C: CurveAffine,
    ProgramChip,
    const K: usize,
    const MAX_WORDS: usize,
    const PAR: usize
> where
    ProgramChip: HashRoundInstructions<C, K, MAX_WORDS> + Clone,
{
    chips: [ProgramChip; PAR],
    #[allow(dead_code)]
    domain: ProgramChip::HashDomains,
    chunk: Vec<C::Base>,
}


impl <
    C: CurveAffine,
    HashRoundChip,
    const K: usize,
    const MAX_WORDS: usize,
    const PAR: usize
> HashChunk<C, HashRoundChip, K, MAX_WORDS, PAR>
where
    HashRoundChip: HashRoundInstructions<C, K, MAX_WORDS> + Clone,
{
    /// Constructs a [`HashChunk`]
    ///
    /// A circuit may have more columns available than are required by a single
    /// `ProgramChip`. To make better use of the available circuit area.
    pub fn construct(
        chips: [HashRoundChip; PAR],
        domain: HashRoundChip::HashDomains,
        chunk: Vec<C::Base>,
    ) -> Self {
        assert_ne!(PAR, 0);
        Self {
            chips,
            domain,
            chunk,
        }
    }
}

const HASH_CHUNK_LEN: usize = 60;

impl <
    C: CurveAffine,
    HashRoundChip,
    const K: usize,
    const MAX_WORDS: usize,
    const PAR: usize
> HashChunk<C, HashRoundChip, K, MAX_WORDS, PAR>
    where
        HashRoundChip: HashRoundInstructions<C, K, MAX_WORDS> + Clone,
{
    pub fn calculate_chunk_hash(
        &self,
        init: HashRoundChip::Var,
        mut layouter: impl Layouter<C::Base>,
    ) -> Result<HashRoundChip::Var, Error> {
        // currently, chunk refers to instruction.
        // each instruction is 32 bit length, so we take 60 instructions as a chunk.

        assert_eq!(self.chunk.len() % HASH_CHUNK_LEN, 0);
        let chunk_length = self.chunk.len() / HASH_CHUNK_LEN;

        let chunks_per_chip = (chunk_length + PAR - 1) / PAR;

        let chips = (0..chunk_length).map(|i|{
            self.chips[i / chunks_per_chip].clone()
        });

        // For each chunk (60 instructions), we split them to element, each element
        // is a 7.5*32 = 240 bit data, apparently, we need decompose check.
        let mut decomposed_chunk = Vec::<Value<C::Base>>::new();
        let chunk = &self.chunk;
        let two_power_32 = Value::known(C::Base::from(1<<32));
        let two_power_16 = Value::known(C::Base::from(1<<16));

        let mut r = 0;
        while r < self.chunk.len() {
            for _ in 0..4 {
                let mut v = Value::known(C::Base::from(0));
                for i in 0..7 {
                    v = v * two_power_32;
                    v = v + Value::known(chunk[r+i]);
                }
                v = v * two_power_16;

                // decompose the chunk[r+7] to high 16 bits and low 16 bits
                let chunk_7_str = format!("{:?}", chunk[r+7]);
                let chunk_7_len = chunk_7_str.len();
                let chunk_7_slice = &chunk_7_str.as_bytes()[chunk_7_len-8..];
                let mut high_16_bit = 0u32;
                for k in 0..4 {
                    high_16_bit <<= 4;
                    let t = if chunk_7_slice[k] >= '0' as u8 &&  chunk_7_slice[k] <= '9' as u8 {
                        chunk_7_slice[k] - '0' as u8
                    } else {
                        10 + chunk_7_slice[k] - 'a' as u8
                    };
                    high_16_bit |= t as u32;
                }

                let high_16_bit = Value::known(C::Base::from(high_16_bit as u64));
                let low_16_bit  = Value::known(chunk[r+7]) - (high_16_bit * two_power_16);
                v = v + low_16_bit;  // plus low 16 bit
                decomposed_chunk.push(v);

                // println!("v: {:?}", v);

                let mut v = Value::known(C::Base::from(0));
                v = v + high_16_bit; // plus high 16 bit
                for i in 8..15 {
                    v = v * two_power_32;
                    v = v + Value::known(chunk[r+i]);
                }
                decomposed_chunk.push(v);
                // println!("v: {:?}", v);

                r += 15;
            }
            // r increase 60=4*15 every loop, and store 8 element
        }

        let mut pre = init;
        for (l, chip) in chips.enumerate() {
            pre = chip.hash_round(
                layouter.namespace(|| format!("hash(chunk_{})", l)),
                    Q.clone(),
                pre.clone(),
                decomposed_chunk[l*8..l*8+8].try_into().unwrap()
            )?;
        }

        Ok(pre)
    }
}

lazy_static! {
    static ref COMMIT_DOMAIN: sinsemilla::CommitDomain =
        sinsemilla::CommitDomain::new(PERSONALIZATION);
    static ref Q: pallas::Affine = COMMIT_DOMAIN.Q().to_affine();
    static ref R: pallas::Affine = COMMIT_DOMAIN.R().to_affine();
    static ref R_ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*R, NUM_WINDOWS).unwrap();
    static ref BASE: pallas::Affine = pallas::Point::generator().to_affine();
    static ref ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS).unwrap();
    static ref ZS_AND_US_SHORT: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap();
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProgramHashDomain;
impl HashDomains<pallas::Affine> for ProgramHashDomain {
    #[allow(non_snake_case)]
    fn Q(&self) -> pallas::Affine {
        *Q
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProgramCommitDomain;
impl CommitDomains<pallas::Affine, ProgramFixedBases, ProgramHashDomain> for ProgramCommitDomain {
    fn r(&self) -> FullWidth {
        FullWidth::from_parts(*R, &R_ZS_AND_US)
    }

    fn hash_domain(&self) -> ProgramHashDomain {
        ProgramHashDomain
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct ProgramFixedBases;
impl FixedPoints<pallas::Affine> for ProgramFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}

#[derive(Debug, Eq, PartialEq, Clone)]
struct FullWidth(pallas::Affine, &'static [(u64, [pallas::Base; H])]);
#[derive(Debug, Eq, PartialEq, Clone)]
struct BaseField;
#[derive(Debug, Eq, PartialEq, Clone)]
struct Short;

impl FullWidth {
    #[allow(dead_code)]
    fn from_pallas_generator() -> Self {
        FullWidth(*BASE, &ZS_AND_US)
    }

    fn from_parts(
        base: pallas::Affine,
        zs_and_us: &'static [(u64, [pallas::Base; H])],
    ) -> Self {
        FullWidth(base, zs_and_us)
    }
}

impl FixedPoint<pallas::Affine> for BaseField {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for Short {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US_SHORT
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US_SHORT.iter().map(|(z, _)| *z).collect()
    }
}


/// build the program hash constraint
/// ensure the running program is indeed the claimed one, i.e., the program correspond
/// the preimage of the public hash
/// here we write circuit to ensure the hash computation process is correct
///
/// we defined the program witness struct, here we take the
/// struct and load the program into plonkish table.
/// 1. load the program to a lookup table.
/// 2. copy the table content to sinsemilla hash table.
#[allow(dead_code)]
#[derive(Clone)]
struct ProgramTableConfig {
    // to check whether a given (address, instruction) in the below two lookup table
    addrs: TableColumn,        // store addresses as a lookup table
    instructions: TableColumn, // store instructions as a lookup table

    // todo: remove it after knowing how to get AssignedCell from a table
    a: Column<Advice>,   // store constant in this column

    // not sure whether put sinsemilla hash table here.
    // actually, we have two sinsemilla chips here, we need to share the data to the two chips.
    hash_config: [HashRoundConfig<ProgramHashDomain, ProgramCommitDomain, ProgramFixedBases>; 2],
    instance: Column<Instance>,
    constants: Column<Fixed>,
}


struct ProgramTableChip<F: PrimeFieldBits> {
    config: ProgramTableConfig,
    _maker: PhantomData<F>,
}


#[allow(dead_code)]
impl ProgramTableChip<pallas::Base> {
    pub fn construct(config: ProgramTableConfig) -> Self {
        Self {
            config,
            _maker: PhantomData,
        }
    }


    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
    ) -> ProgramTableConfig {
        let col_a = meta.advice_column();
        meta.enable_equality(col_a);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // Shared fixed column for loading constants
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        let addr_lookup_table = meta.lookup_table_column();
        let instructions_lookup_table = meta.lookup_table_column();


        // ------------------------- create sinsemilla circuit -------------------
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // NB: In the actual Action circuit, these fixed columns will be reused
        // by other chips. For this test, we are creating new fixed columns.
        let fixed_y_q_1 = meta.fixed_column();
        let fixed_y_q_2 = meta.fixed_column();

        // Fixed columns for the Sinsemilla generator lookup table
        let lookup = (
            meta.lookup_table_column(),
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], lookup.0);

        let sinsemilla_config_1 = SinsemillaChip::configure(
            meta,
            advices[5..].try_into().unwrap(),
            advices[7],
            fixed_y_q_1,
            lookup,
            range_check,
        );

        let sinsemilla_config_2 = SinsemillaChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            advices[2],
            fixed_y_q_2,
            lookup,
            range_check,
        );

        let program_config_1 = HashRoundChip::configure(
            meta,
            advices[5..].try_into().unwrap(),
            sinsemilla_config_1
        );

        let program_config_2 = HashRoundChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            sinsemilla_config_2
        );

        ProgramTableConfig {
            addrs: addr_lookup_table,
            instructions: instructions_lookup_table,
            a: col_a,
            hash_config: [program_config_1, program_config_2],
            instance,
            constants,
        }
    }

    /// load the program witness struct into the circuit table
    #[allow(dead_code)]
    pub fn load_private_program(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        program: &Program
    ) -> Result<(), Error> {

        layouter.assign_table(
            || "assign program table",
            |mut table| {
                let (mut cur_segment, mut cur_instruction) = (0, 0);
                let mut index = 0;
                loop {
                    match program.next_instruction(cur_segment, cur_instruction) {
                        (None, _, _) => {
                            break
                        }
                        (Some(instruction), cursor1, cursor2) => {
                            table.assign_cell(
                                || "program_table_addr",
                                self.config.addrs,
                                index,
                                || Value::known(pallas::Base::from(instruction.addr as u64))
                            )?;

                            table.assign_cell(
                                || "program_table_instruction",
                                self.config.instructions,
                                index,
                                || Value::known(pallas::Base::from(instruction.bytecode as u64))
                            )?;

                            index += 1;
                            cur_segment = cursor1;
                            cur_instruction = cursor2;
                        }
                    }
                }
                println!("loaded {} instructions", index);
                Ok(())
            }
        )?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn calculate_final_hash(
        &self,
        layouter: impl Layouter<pallas::Base>,
        q_cell: AssignedCell<pallas::Base, pallas::Base>,
        chips: [HashRoundChip<ProgramHashDomain, ProgramCommitDomain, ProgramFixedBases>; 2],
        program: &Program,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {

        // fetch 120 instructions, if less than 120, then pad with zeros
        let (mut cur_segment, mut cur_instruction) = (0, 0);
        let mut fetch_chunk_120 = || {
            let mut cnt = 0;
            let mut chunk = vec![];
            let mut done: bool = false;
            loop {
                match program.next_instruction(cur_segment, cur_instruction) {
                    (None, _, _) => {
                        break
                    },
                    (Some(instruction), cursor1, cursor2) => {
                        (cur_segment, cur_instruction) = (cursor1, cursor2);
                        chunk.push(
                            pallas::Base::from(instruction.bytecode as u64)
                        );
                        cnt += 1;
                        if cnt >= 120 {
                            break
                        }
                    }
                }
            }
            if chunk.len() < 120 {
                for _ in chunk.len()..120 {
                    chunk.push(pallas::Base::zero());
                }
                done = true;
            }
            (chunk, done)
        };

        let mut chunk: Vec<pallas::Base> = vec![];
        loop {
            let (a_chunk, done) = fetch_chunk_120();
            chunk.extend(a_chunk);
            if done {
                break;
            }
        }

        let program_chunk = HashChunk::construct(
            chips, ProgramHashDomain, chunk
        );

        // Q in fixed column, assign it as a cell
        let hash = program_chunk.calculate_chunk_hash(
            q_cell,
            layouter
        )?;

        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use elf::ElfBytes;
    use elf::endian::AnyEndian;
    use halo2_gadgets::sinsemilla::chip::SinsemillaChip;
    use halo2_proofs::arithmetic::CurveAffine;
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::pasta::pallas;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    use mips_emulator::state::State;
    use mips_emulator::witness::{Instruction, Program, ProgramSegment};
    use crate::program::{ProgramCommitDomain, ProgramFixedBases, ProgramHashDomain, ProgramTableChip, ProgramTableConfig, Q};
    use crate::program::chip::HashRoundChip;

    struct MyCircuit {
        program: Program
    }

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = ProgramTableConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit {
                program: Program::new()
            }
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            ProgramTableChip::configure(meta)
        }

        fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<pallas::Base>) -> Result<(), Error> {
            // load generator table (shared across both configs)
            SinsemillaChip::<ProgramHashDomain, ProgramCommitDomain, ProgramFixedBases>::load(
                config.hash_config[0].sinsemilla_config.clone(),
                &mut layouter,
            )?;

            // construct program table chip
            let chip = ProgramTableChip::construct(config.clone());
            chip.load_private_program(&mut layouter, &self.program)?;

            // construct program chip
            let chip_1 = HashRoundChip::construct(config.hash_config[0].clone());
            let chip_2 = HashRoundChip::construct(config.hash_config[1].clone());

            let q_cell = layouter.assign_region(|| "Q", |mut region|{
                let a = region.assign_advice_from_instance(
                    || "Q",
                    config.instance,
                    0,
                    config.a,
                    0);
                a
            })?;

            // todo: ensure the calculated final hash equal to hash in instance column
            let hash = chip.calculate_final_hash(layouter, q_cell, [chip_1, chip_2], &self.program)?;

            hash.value().map(|h| {
                println!("hash by circuit: {:?}", h);
            });

            Ok(())
        }
    }

    #[test]
    fn test_simple_program() {
        let mut program = Program::new();
        program.segments.push(
            ProgramSegment {
                start_addr: 0,
                segment_size: 0x40,
                instructions: vec![
                    Instruction {
                        addr: 0x00000000,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x00000004,
                        bytecode: 0xfedcba98,
                    },
                    Instruction {
                        addr: 0x00000008,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x0000000c,
                        bytecode: 0x00000002,
                    },
                    Instruction {
                        addr: 0x00000010,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x00000014,
                        bytecode: 0x00000004,
                    },
                    Instruction {
                        addr: 0x00000018,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x0000001c,
                        bytecode: 0xcdef1234,
                    },
                    Instruction {
                        addr: 0x00000020,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x00000024,
                        bytecode: 0x00000008,
                    },
                    Instruction {
                        addr: 0x00000028,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x0000002c,
                        bytecode: 0x0000000a,
                    },
                    Instruction {
                        addr: 0x00000030,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x00000034,
                        bytecode: 0x0000000c,
                    },
                    Instruction {
                        addr: 0x00000038,
                        bytecode: 0x76543210,
                    },
                    Instruction {
                        addr: 0x0000003c,
                        bytecode: 0x0000000e,
                    },
                ]
            }
        );

        let mut circuit = MyCircuit {
            program
        };

        println!("created circuit start running");
        let coordinates = Q.clone().coordinates().unwrap();
        let prover = MockProver::run(11, &circuit, vec![vec![*coordinates.x()]]).unwrap();
        prover.assert_satisfied();

        let res = circuit.program.compute_hash();
        println!("hash by program: {:?}", res);
    }

    #[test]
    #[cfg(feature = "dev-graph")]
    fn print_simple_program() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("program-layout.png", (1024, 7680)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Program Table", ("sans-serif", 60)).unwrap();

        let mut program = Program::new();
        program.segments.push(
            ProgramSegment {
                start_addr: 0,
                segment_size: 0x08,
                instructions: vec![
                    Instruction {
                        addr: 0x00000000,
                        bytecode: 0x00000001,
                    },
                    Instruction {
                        addr: 0x00000004,
                        bytecode: 0x00000002,
                    }
                ]
            }
        );

        let circuit = MyCircuit {
            program
        };

        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(false)
            .render(11, &circuit, &root)
            .unwrap();
    }

    #[test]
    fn test_hello_world() {
        let path = PathBuf::from("../mips-emulator/example/bin/hello.elf");
        let data = fs::read(path).expect("could not read file");
        let file = ElfBytes::<AnyEndian>::minimal_parse(
            data.as_slice()
        ).expect("opening elf file failed");

        let (mut state, mut program) = State::load_elf(&file);

        state.patch_go(&file);
        state.patch_stack();

        program.load_instructions(&mut state);
        let res = program.compute_hash();
        println!("hash by program: {:?}", res);

        let circuit = MyCircuit {
            program: *program
        };

        println!("created circuit start running");
        let coordinates = Q.clone().coordinates().unwrap();
        let prover = MockProver::run(19, &circuit, vec![vec![*coordinates.x()]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    #[cfg(feature = "dev-graph")]
    fn print_hello_world() {
        let path = PathBuf::from("../mips-emulator/example/bin/hello.elf");
        let data = fs::read(path).expect("could not read file");
        let file = ElfBytes::<AnyEndian>::minimal_parse(
            data.as_slice()
        ).expect("opening elf file failed");

        let (mut state, mut program) = State::load_elf(&file);

        state.patch_go(&file);
        state.patch_stack();

        program.load_instructions(&mut state);

        let circuit = MyCircuit {
            program: *program
        };

        use plotters::prelude::*;

        let root = BitMapBackend::new("program-hello-world-layout.png", (1024, 7680)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Program Table", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(false)
            .render(20, &circuit, &root)
            .unwrap();
    }
}
