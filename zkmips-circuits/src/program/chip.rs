use halo2_gadgets::{
    sinsemilla::{
        CommitDomains, HashDomains, MessagePiece, SinsemillaInstructions,
        chip::{SinsemillaChip, SinsemillaConfig},
        primitives as sinsemilla,
    },
    utilities::{RangeConstrained, UtilitiesInstructions},
    ecc::FixedPoints,
};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    halo2curves::pasta::pallas,
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use crate::program::HashRoundInstructions;


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashRoundConfig<Hash, Commit, Fixed>
where
    Hash: HashDomains<pallas::Affine>,
    Fixed: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, Fixed, Hash>,
{
    advices: [Column<Advice>; 5],
    pub(super) sinsemilla_config: SinsemillaConfig<Hash, Commit, Fixed>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashRoundChip<Hash, Commit, Fixed>
where
    Hash: HashDomains<pallas::Affine>,
    Fixed: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, Fixed, Hash>,
{
    config: HashRoundConfig<Hash, Commit, Fixed>
}

impl<Hash, Commit, Fixed> Chip<pallas::Base> for HashRoundChip<Hash, Commit, Fixed>
where
    Hash: HashDomains<pallas::Affine>,
    Fixed: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, Fixed, Hash>,
{
    type Config = HashRoundConfig<Hash, Commit, Fixed>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<Hash, Commit, F> HashRoundChip<Hash, Commit, F>
where
    Hash: HashDomains<pallas::Affine>,
    F: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    pub fn configure(
        _meta: &mut ConstraintSystem<pallas::Base>,
        sinsemilla_advices: [Column<Advice>; 5],
        sinsemilla_config: SinsemillaConfig<Hash, Commit, F>,
    ) -> HashRoundConfig<Hash, Commit, F> {
        // All five advice columns are equality-enabled by SinsemillaConfig.

        // todo: check that pieces have been decomposed correctly for sinsemilla hash

        HashRoundConfig {
            advices: sinsemilla_advices,
            sinsemilla_config
        }
    }

    pub fn construct(config: HashRoundConfig<Hash, Commit, F>) -> Self {
        HashRoundChip { config }
    }
}

impl<Hash, Commit, F>
    HashRoundInstructions<pallas::Affine, { sinsemilla::K }, { sinsemilla::C }>
    for HashRoundChip<Hash, Commit, F>
where
    Hash: HashDomains<pallas::Affine> + Eq,
    F: FixedPoints<pallas::Affine>,
    Commit: CommitDomains<pallas::Affine, F, Hash> + Eq,
{
    #[allow(non_snake_case)]
    fn hash_round(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        Q: pallas::Affine,
        pre: Self::Var,
        chunks: [Value<pallas::Base>; 8],
    ) -> Result<Self::Var, Error> {
        let pre = MessagePiece::from_subpieces(
            self.clone(),
            layouter.namespace(|| "witness pre hash"),
            [RangeConstrained::bitrange_of(pre.value(), 0..250)]
        )?;

        let mut chunks_pieces = Vec::with_capacity(9);
        chunks_pieces.push(pre.inner());

        // chunk is 8 length 240 bit data
        for chunk in chunks.into_iter() {
            let chunk_piece = MessagePiece::from_subpieces(
                self.clone(),
                layouter.namespace(|| "witness chunk"),
                [RangeConstrained::bitrange_of(chunk.as_ref(), 0..240)]
            )?;
            chunks_pieces.push( chunk_piece.inner() );
        }

        let (point, _) = self.hash_to_point(
            layouter.namespace(|| "hash chunks"),
            Q,
            chunks_pieces.into(),
        )?;
        let hash = Self::extract(&point);

        // todo: `SinsemillaChip::hash_to_point` returns the running sum for each `MessagePiece`.
        // Grab the outputs we need for the decomposition constraints.

        Ok(hash)
    }
}

impl<Hash, Commit, F> UtilitiesInstructions<pallas::Base> for HashRoundChip<Hash, Commit, F>
    where
        Hash: HashDomains<pallas::Affine>,
        F: FixedPoints<pallas::Affine>,
        Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    type Var = AssignedCell<pallas::Base, pallas::Base>;
}

impl<Hash, Commit, F> SinsemillaInstructions<pallas::Affine, { sinsemilla::K }, { sinsemilla::C }>
for HashRoundChip<Hash, Commit, F>
    where
        Hash: HashDomains<pallas::Affine>,
        F: FixedPoints<pallas::Affine>,
        Commit: CommitDomains<pallas::Affine, F, Hash>,
{
    type CellValue = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::CellValue;

    type Message = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::Message;
    type MessagePiece = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::MessagePiece;
    type RunningSum = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::RunningSum;

    type X = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::X;
    type NonIdentityPoint = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::NonIdentityPoint;
    type FixedPoints = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::FixedPoints;

    type HashDomains = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::HashDomains;
    type CommitDomains = <SinsemillaChip<Hash, Commit, F> as SinsemillaInstructions<
        pallas::Affine,
        { sinsemilla::K },
        { sinsemilla::C },
    >>::CommitDomains;

    fn witness_message_piece(
        &self,
        layouter: impl Layouter<pallas::Base>,
        value: Value<pallas::Base>,
        num_words: usize,
    ) -> Result<Self::MessagePiece, Error> {
        let config = self.config().sinsemilla_config.clone();
        let chip = SinsemillaChip::<Hash, Commit, F>::construct(config);
        chip.witness_message_piece(layouter, value, num_words)
    }

    #[allow(non_snake_case)]
    #[allow(clippy::type_complexity)]
    fn hash_to_point(
        &self,
        layouter: impl Layouter<pallas::Base>,
        Q: pallas::Affine,
        message: Self::Message,
    ) -> Result<(Self::NonIdentityPoint, Vec<Vec<Self::CellValue>>), Error> {
        let config = self.config().sinsemilla_config.clone();
        let chip = SinsemillaChip::<Hash, Commit, F>::construct(config);
        chip.hash_to_point(layouter, Q, message)
    }

    fn extract(point: &Self::NonIdentityPoint) -> Self::X {
        SinsemillaChip::<Hash, Commit, F>::extract(point)
    }
}
