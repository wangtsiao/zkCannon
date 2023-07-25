//! Define generic Word type with utility functions
// Naming Convesion
// - Limbs: An MIPS word is 32 bits. Limbs N means split 32 into N limb. For example, N = 4, each
//   limb is 32/4 = 8 bits

use std::collections::HashMap;
use halo2_proofs::{
    plonk::{
        Column, Advice, VirtualCells, Expression, ConstraintSystem, Error,
        Challenge, FirstPhase, SecondPhase
    },
    circuit::{Value, AssignedCell, Layouter},
    poly::Rotation,
    arithmetic::Field,
};
use halo2_proofs::circuit::Region;
use num_traits::{One, Signed, Zero, FromPrimitive};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::{Shl, BitAnd};

pub mod cell_manager;
pub mod cell_manager_strategy;
pub use cell_manager::{Cell, CellType, Table, CellManagerColumns, CellManager, CellManagerStrategy};
pub use cell_manager_strategy::CMFixedWidthStrategy;

pub fn int_to_field<T, const N_BITS: usize, F: Field>(int: T) -> F
    where
        T: Debug + Copy + Shl<Output = T> + BitAnd<Output = T> + PartialEq + One + Zero + FromPrimitive,
{
    let mut res: F = F::ZERO;
    let mut mask: T = T::one();
    for i in (0..N_BITS).rev() {
        mask = T::one().shl(T::from_usize(i).unwrap());
        res = res.double();
        if (int & mask) != T::zero() {
            res += F::ONE;
        }
    }
    res
}

/// mips word 4 bytes, half word 2 bytes
const N_BYTES_HALF_WORD: usize = 2;

/// The MIPS word for witness
#[derive(Clone, Debug, Copy)]
pub struct WordLimbs<T, const N: usize> {
    /// The limbs of this word.
    pub limbs: [T; N],
}

pub type Word2<T> = WordLimbs<T, 2>;

pub type Word4<T> = WordLimbs<T, 4>;

pub type Word8<T> = WordLimbs<T, 8>;

impl<T, const N: usize> WordLimbs<T, N> {
    /// Constructor
    pub fn new(limbs: [T; N]) -> Self {
        Self { limbs }
    }
    /// The number of limbs
    pub fn n() -> usize {
        N
    }
}

impl<const N: usize> WordLimbs<Column<Advice>, N> {
    /// Query advice of WordLibs of columns advice
    pub fn query_advice<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        at: Rotation,
    ) -> WordLimbs<Expression<F>, N> {
        WordLimbs::new(self.limbs.map(|column| meta.query_advice(column, at)))
    }
}

impl<const N: usize> WordLimbs<u8, N> {
    /// Convert WordLimbs of u8 to WordLimbs of expressions
    pub fn to_expr<F: Field>(&self) -> WordLimbs<Expression<F>, N> {
        WordLimbs::new(self.limbs.map(|v| Expression::Constant(
            int_to_field::<u8, 8, F>(v)
        )))
    }
}

impl<T: Default, const N: usize> Default for WordLimbs<T, N> {
    fn default() -> Self {
        Self {
            limbs: [(); N].map(|_| T::default()),
        }
    }
}

pub trait Expr<F: Field> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}
impl<F: Field> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(
            int_to_field::<u64, 64, F>(self.unsigned_abs() as u64) * if self.is_negative() { -F::ONE } else { F::ONE },
        )
    }
}
impl<F: Field> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}


/// Steal the expression from gate
pub fn query_expression<F: Field, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0.expr())
    });
    expr.unwrap()
}

/// All challenges used in `SuperCircuit`.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    lookup_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        // Dummy columns are required in the test circuits
        // In some tests there might be no advice columns before the phase, so Halo2 will panic with
        // "No Column<Advice> is used in phase Phase(1) while allocating a new 'Challenge usable
        // after phase Phase(1)'"
        // #[cfg(any(test, feature = "test-circuits"))]
        // let _dummy_cols = [meta.advice_column(), meta.advice_column_in(SecondPhase)];

        Self {
            lookup_input: meta.challenge_usable_after(FirstPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn expr<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [lookup_input] = query_expression(meta, |meta| {
            [self.lookup_input].map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
    }
}

impl<T: Clone> Challenges<T> {
    /// Returns challenge of `lookup_input`.
    pub fn lookup_input(&self) -> T {
        self.lookup_input.clone()
    }

    /// Returns the challenges indexed by the challenge index
    pub fn indexed(&self) -> &T {
        &self.lookup_input
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness
    fn powers_of<const S: usize>(base: Expression<F>) -> [Expression<F>; S] {
        std::iter::successors(base.clone().into(), |power| {
            (base.clone() * power.clone()).into()
        })
            .take(S)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Returns powers of randomness for lookups
    pub fn lookup_input_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.lookup_input.clone())
    }
}
