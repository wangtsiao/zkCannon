use super::*;

#[derive(Clone, Debug)]
pub struct RandomLinearCombination<F, const N: usize> {
    // random linear combination expression of cells
    expression: Expression<F>,
    // inner cells in little-endian for synthesis
    pub(crate) cells: [Cell<F>; N],
}

impl<F: Field, const N: usize> RandomLinearCombination<F, N> {
    /// XXX for randomness 256.expr(), consider using IntDecomposition instead
    pub(crate) fn new(cells: [Cell<F>; N], randomness: Expression<F>) -> Self {
        Self {
            expression: rlc::expr(&cells.clone().map(|cell| cell.expr()), randomness),
            cells,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        bytes: Option<[u8; N]>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        bytes.map_or(Err(Error::Synthesis), |bytes| {
            self.cells
                .iter()
                .zip(bytes.iter())
                .map(|(cell, byte)| {
                    cell.assign(region, offset, Value::known(int_to_field::<u8, 8, F>(*byte)))
                })
                .collect()
        })
    }
}

impl<F: Field, const N: usize> Expr<F> for RandomLinearCombination<F, N> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

// TODO: implement Int Decomposition
pub(crate) mod rlc {
    use std::ops::{Add, Mul};

    use crate::util::Expr;
    use super::{Field, int_to_field};
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field, E: Expr<F>>(expressions: &[E], randomness: E) -> Expression<F> {
        if !expressions.is_empty() {
            generic(expressions.iter().map(|e| e.expr()), randomness.expr())
        } else {
            0.expr()
        }
    }

    pub(crate) fn value<'a, F: Field, I>(values: I, randomness: F) -> F
        where
            I: IntoIterator<Item = &'a u8>,
            <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let values = values
            .into_iter()
            .map(|v| int_to_field::<u8, 8, F>(*v))
            .collect::<Vec<F>>();
        if !values.is_empty() {
            generic(values, randomness)
        } else {
            F::ZERO
        }
    }

    fn generic<V, I>(values: I, randomness: V) -> V
        where
            I: IntoIterator<Item = V>,
            <I as IntoIterator>::IntoIter: DoubleEndedIterator,
            V: Clone + Add<Output = V> + Mul<Output = V>,
    {
        let mut values = values.into_iter().rev();
        let init = values.next().expect("values should not be empty");

        values.fold(init, |acc, value| acc * randomness.clone() + value)
    }
}
