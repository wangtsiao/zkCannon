use crate::mips_circuit::execution::add::AddGadget;
use crate::table::LookupTable;
use super::*;
mod add;

pub trait ExecutionGadget<F: Field> {
    const NAME: &'static str;

    const OPCODE_ID: OpcodeId;

    fn configure(meta: &mut MIPSConstraintBuilder<F>) -> Self;

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionRow,
    ) -> Result<(), Error>;
}


#[derive(Debug, Clone)]
pub struct ExecutionConfig<F> {
    // MIPS Circuit selector, which enables all usable rows. The rows where this selector is
    // disabled won't verify any constraint (they can be unused rows or rows with blinding
    // factors).
    q_usable: Selector,
    // Dynamic selector that is enabled at the rows where each assigned execution step starts (a
    // step has dynamic height).
    q_step: Column<Advice>,
    // gadgets
    add_gadget: AddGadget<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        opcode_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
    ) -> Self {
        let q_usable = meta.complex_selector();
        let q_step = meta.advice_column();

        Self {
            q_usable,
            q_step,
            _marker: PhantomData::default(),
        }
    }
}
