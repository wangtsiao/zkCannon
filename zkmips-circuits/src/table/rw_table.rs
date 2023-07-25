use super::*;

#[derive(Debug, Copy, Clone)]
pub struct RwTable {
    // Read Write Counter
    pub rw_counter: Column<Advice>,
    // Is Write
    pub is_write: Column<Advice>,
    // Address
    pub address: Column<Advice>,
    // Value
    pub value: Column<Advice>,
    // Value Previous
    pub value_prev: Column<Advice>,
    // Init Value
    pub init_value: Column<Advice>,
}

impl<F: Field> LookupTable<F> for RwTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.rw_counter.into(),
            self.is_write.into(),
            self.address.into(),
            self.value.into(),
            self.value_prev.into(),
            self.init_value.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("rw_counter"),
            String::from("is_write"),
            String::from("address"),
            String::from("value"),
            String::from("value_prev"),
            String::from("init_value"),
        ]
    }
}

impl RwTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            address: meta.advice_column(),
            value: meta.advice_column(),
            value_prev: meta.advice_column(),
            init_value: meta.advice_column(),
        }
    }

    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &RwRow<Value<F>>
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.rw_counter, row.rw_counter),
            (self.is_write, row.is_write),
            (self.address, row.address),
            (self.value, row.value),
            (self.value_prev, row.value_prev),
            (self.init_value, row.init_value)
        ] {
            region.assign_advice(|| "assign rw row on rw table", column, offset, || value)?;
        }
        Ok(())
    }

    /// Assign the `RwTable` from a `RwMap`
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        rws: &[MemoryAccess],
        n_rows: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "rw table",
            |mut region| self.load_with_region(&mut region, rws, n_rows),
        )
    }

    pub(crate) fn load_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        rws: &[MemoryAccess],
        n_rows: usize,
    ) -> Result<(), Error> {
        let (rows, _) = RwVec::table_assignments_prepad(rws, n_rows);
        for (offset, row) in rows.iter().enumerate() {
            self.assign(region, offset, &RwRow::<Value<F>>::table_assignment(row))?;
        }
        Ok(())
    }
}


#[derive(Copy, Clone, Debug)]
pub struct RwRow<F> {
    pub rw_counter: F,
    pub is_write: F,
    pub address: F,
    pub value: F,
    pub value_prev: F,
    pub init_value: F,
}

impl<F: Field> RwRow<F> {
    pub fn values(&self) -> [F; 6] {
        [
            self.rw_counter,
            self.is_write,
            self.address,
            self.value,
            self.value_prev,
            self.init_value,
        ]
    }
}

impl<F: Field> RwRow<Value<F>> {
    pub fn table_assignment(mem_access: &MemoryAccess) -> Self {
        let rw_counter: F = int_to_field::<u64, 64, F>(mem_access.rw_counter);
        let is_write = if matches!(mem_access.op, MemoryOperation::Write) {
            F::ONE
        } else {
            F::ZERO
        };
        let address= int_to_field::<u32, 32, F>(mem_access.addr);
        let value = int_to_field::<u32, 32, F>(mem_access.value);
        let value_prev = int_to_field::<u32, 32, F>(mem_access.value_prev);
        let init_value = F::ZERO;

        Self {
            rw_counter: Value::known(rw_counter),
            is_write: Value::known(is_write),
            address: Value::known(address),
            value: Value::known(value),
            value_prev: Value::known(value_prev),
            init_value: Value::known(init_value),
        }
    }

    pub fn unwrap(self) -> RwRow<F> {
        let unwrap_f = |f: Value<F>| {
            let mut inner = None;
            _ = f.map(|v| {
                inner = Some(v);
            });
            inner.unwrap()
        };

        RwRow {
            rw_counter: unwrap_f(self.rw_counter),
            is_write: unwrap_f(self.is_write),
            address: unwrap_f(self.address),
            value: unwrap_f(self.value),
            value_prev: unwrap_f(self.value_prev),
            init_value: unwrap_f(self.init_value),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct RwVec(pub Vec<MemoryAccess>);

impl Index<usize> for RwVec {
    type Output = MemoryAccess;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl RwVec {
    /// Check rw_counter is continuous and starting from 1
    pub fn check_rw_counter_sanity(&self)  {
        for (idx, rw_counter) in self.0
            .iter()
            .map(|r| r.rw_counter)
            .sorted()
            .enumerate()
        {
            debug_assert_eq!(idx as u64, rw_counter-1);
        }
    }

    /// Build Rws for assignment
    pub fn table_assignments(&mut self) {
        self.0.sort_by_key(|row| {
            (
                row.addr,
                row.rw_counter,
            )
        });
    }

    /// Calculates the number of Rw::Start rows needed.
    /// `target_len` is allowed to be 0 as an "auto" mode,
    /// then only 1 Rw::Start row will be prepadded.
    pub(crate) fn padding_len(rows_len: usize, target_len: usize) -> usize {
        if target_len > rows_len {
            target_len - rows_len
        } else {
            if target_len != 0 {
                panic!(
                    "RwVec::padding_len overflow, target_len: {}, rows_len: {}",
                    target_len, rows_len
                );
            }
            1
        }
    }

    /// Prepad rows to target length
    pub fn table_assignments_prepad(rows: &[MemoryAccess], target_len: usize)
        -> (Vec<MemoryAccess>, usize) {
        // Remove Start rows as we will add them from scratch.
        let rows: Vec<MemoryAccess> = rows
            .iter()
            .cloned()
            .collect();
        let padding_length = Self::padding_len(rows.len(), target_len);
        let padding = (1..=padding_length)
            .map(|rw_counter| MemoryAccess::default());
        (padding.chain(rows.into_iter()).collect(), padding_length)
    }
}


#[cfg(test)]
mod tests {
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::halo2curves::pasta::pallas;
    use crate::table::rw_table::int_to_field;

    #[test]
    fn test_int_to_field() {
        assert_eq!(int_to_field::<u64, 64, pallas::Base>(0), pallas::Base::ZERO);
        let mut ans = pallas::Base::ZERO;
        for _ in 0..3423 {
            ans += pallas::Base::ONE;
        }

        assert_eq!(int_to_field::<u64, 64, pallas::Base>(3423), ans);
    }
}
