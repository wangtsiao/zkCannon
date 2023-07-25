use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Error};
use mips_emulator::opcode_id::OpcodeId;
use mips_emulator::witness::ExecutionRow;
use crate::util::{Cell, int_to_field};
use super::{ExecutionGadget, MIPSConstraintBuilder};

pub struct AddGadget<F> {
    opcode: Cell<F>,
    lhs: Cell<F>,
    rhs: Cell<F>,
    out: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for AddGadget<F> {
    const NAME: &'static str = "ADD";
    const OPCODE_ID: OpcodeId = OpcodeId::ADD;

    fn configure(cb: &mut MIPSConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let lhs = cb.query_cell();
        let rhs = cb.query_cell();
        let out = cb.query_cell();
        // todo: create gate 1, opcode is correct
        // todo: create gate 2, lhs, rhs is decoded correctly
        // todo: create gate 3, lhs + rhs == out
        // todo: create
        Self {
            opcode,
            lhs,
            rhs,
            out,
        }
    }

    fn assign_exec_step(&self, region: &mut Region<'_, F>, offset: usize, step: &ExecutionRow) -> Result<(), Error> {
        self.opcode.assign(
            region, offset, Value::known(int_to_field::<u32, 32, F>(step.instruction.bytecode))
        )?;
        // todo: decomposition the bytecode
        let (rhs, lhs, out) = (0, 0, 0);
        self.rhs.assign(
            region, offset, Value::known(int_to_field::<u32, 32, F>(rhs))
        )?;
        self.lhs.assign(
            region, offset, Value::known(int_to_field::<u32, 32, F>(lhs))
        )?;
        self.out.assign(
            region, offset, Value::known(int_to_field::<u32, 32, F>(out))
        )?;
        Ok(())
    }
}
