use super::*;

#[derive(Debug, Copy, Clone)]
pub struct OpcodeTable {
    // Address
    pub address: Column<Advice>,
    // Bytecode
    pub bytecode: Column<Advice>,
}

impl<F: Field> LookupTable<F> for OpcodeTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.address.into(),
            self.bytecode.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("address"),
            String::from("bytecode"),
        ]
    }
}

impl OpcodeTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            address: meta.advice_column(),
            bytecode: meta.advice_column(),
        }
    }

    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: (Value<F>, Value<F>),
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.address, row.0),
            (self.bytecode, row.1)
        ] {
            region.assign_advice(|| "assign bytecode on bytecode table",
                                 column, offset, || value)?;
        }
        Ok(())
    }

    /// Assign the `BytecodeTable` from a `Program`
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        program: &Program,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "bytecode table",
            |mut region| self.load_with_region(&mut region, program),
        )
    }

    pub fn load_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        program: &Program,
    ) -> Result<(), Error> {
        let (mut cur_segment, mut cur_instruction) = (0, 0);
        let mut offset = 0;
        loop {
            match program.next_instruction(cur_segment, cur_instruction) {
                (None, _, _) => {
                    break
                }
                (Some(instruction), cursor1, cursor2) => {
                    let addr = Value::known(
                        int_to_field::<u32, 32, F>(instruction.addr));
                    let bytecode = Value::known(
                        int_to_field::<u32, 32, F>(instruction.bytecode));

                    self.assign(
                        region,
                        offset,
                        (addr, bytecode)
                    )?;

                    offset += 1;
                    cur_segment = cursor1;
                    cur_instruction = cursor2;
                }
            }
        }
        Ok(())
    }
}
