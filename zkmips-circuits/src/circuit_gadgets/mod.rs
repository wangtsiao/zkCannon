//! # ZK MIPS Gadgets
//!
//! A collection of reusable gadgets for the zk mips circuits.

#![allow(dead_code)]

pub mod is_zero;
pub mod util;
pub mod less_than;
pub mod binary_number;
mod batch_is_zero;

use halo2_proofs::plonk::Expression;
use crate::mips_types::Field;


/// Restrict an expression to be a boolean.
pub fn bool_check<F: Field>(value: Expression<F>) -> Expression<F> {
    range_check(value, 2)
}

/// Restrict an expression such that 0 <= word < range.
pub fn range_check<F: Field>(word: Expression<F>, range: usize) -> Expression<F> {
    (1..range).fold(word.clone(), |acc, i| {
        acc * (Expression::Constant(F::from(i as u64)) - word.clone())
    })
}


/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: Field> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        impl<F: crate::mips_types::Field> Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: crate::mips_types::Field> Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);
