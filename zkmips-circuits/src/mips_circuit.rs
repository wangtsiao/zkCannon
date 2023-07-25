use std::marker::PhantomData;
use halo2_proofs::{
    plonk::{
        Selector, Advice, Column, Error, ConstraintSystem, Expression,
        Challenge, FirstPhase, SecondPhase,
    },
    circuit::{Region, AssignedCell, Value,},
    arithmetic::Field,
};
use mips_emulator::{
    opcode_id::OpcodeId,
    witness::ExecutionRow,
};

mod execution;
mod constraint_builder;
mod table;
mod util;

use super::table::{
    OpcodeTable, RwTable,
};
use super::util::{
    Cell, CellManager, CMFixedWidthStrategy, CellType, Table, Expr, Challenges, int_to_field,
};
use table::Lookup;
use util::rlc;
use constraint_builder::MIPSConstraintBuilder;

use mips_emulator::witness::Trace;
use execution::ExecutionConfig;

#[derive(Debug, Clone)]
pub struct MipsCircuitConfig<F> {
    pub execution: ExecutionConfig<F>,
    // External tables
    pub opcode_table: OpcodeTable,
    pub rw_table: RwTable,
    pub _marker: PhantomData<F>,
}

impl<F: Field> MipsCircuitConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        opcode_table: OpcodeTable,
        rw_table: RwTable
    ) -> Self<F> {
        ExecutionConfig::

        Self {

            opcode_table,
            rw_table,
            _marker: PhantomData::default(),
        }
    }
}


#[derive(Debug, Clone)]
pub struct MipsCircuit {
    pub trace: Trace,
    pub config: MipsCircuitConfig,
}
