use std::marker::PhantomData;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Column, ConstraintSystem, Expression, Fixed, VirtualCells, Error},
    poly::Rotation,
};
use crate::mips_types::Field;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    // todo: turn this columns to be table column
    // https://github.com/zcash/halo2/blob/642efc1536d3ea2566b04814bd60a00c4745ae22/halo2_proofs/src/plonk/circuit.rs#L266
    u8: Column<Fixed>,
    u16: Column<Fixed>,
}

impl Config {
    pub fn range_check_u8<F: Field> (
        &self,
        meta: &mut ConstraintSystem<F>,
        name: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(name, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u8, Rotation::cur()))]
        });
    }

    pub fn range_check_u16<F: Field> (
        &self,
        meta: &mut ConstraintSystem<F>,
        name: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(name, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u16, Rotation::cur()))]
        });
    }
}

#[derive(Clone)]
pub struct Queries<F> {
    pub u8: Expression<F>,
    pub u16: Expression<F>,
}

impl<F: Field> Queries<F> {
    pub fn new(meta: &mut VirtualCells<'_, F>, c: Config) -> Self {
        Self {
            u8: meta.query_fixed(c.u8, Rotation::cur()),
            u16: meta.query_fixed(c.u16, Rotation::cur()),
        }
    }
}

pub struct Chip<F: Field> {
    config: Config,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> {
    pub fn construct(config: Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let config = Config {
            u8: meta.fixed_column(),
            u16: meta.fixed_column(),
        };
        meta.annotate_lookup_any_column(config.u8, || "LOOKUP_u8");
        meta.annotate_lookup_any_column(config.u16, || "LOOKUP_u16");
        config
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (column, exponent) in [
            (self.config.u8, 8),
            (self.config.u16, 16),
        ] {
            layouter.assign_region(
                ||format!("assign u{} fixed column", exponent),
                |mut region| {
                    for i in 0..(1<<exponent) {
                        region.assign_fixed(
                            || format!("assign {} in u{} fixed column", i, exponent),
                            column,
                            i,
                            || Value::known(F::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }

        Ok(())
    }
}
