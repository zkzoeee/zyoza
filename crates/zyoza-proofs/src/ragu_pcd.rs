//! Unified `tachyon-zcash/ragu` Non-Uniform Proof-Carrying Data (PCD) & ZK engine over Pasta.
//!
//! Every zero-knowledge proof in Zyoza executes inside a single unified
//! `ragu::Application<'static, Pasta, WalletRank, 5>` with 10 registered `Step<Pasta>` subcircuits:
//! - `Index(0)`: `UnitStep` (`() -> ()`, auxiliary empty right-hand child for unary folds)
//! - `Index(1)`: `MintCircuit` (`() -> LineageHeader`, base seed step committing `[asset, genesis, latest, acc]`)
//! - `Index(2)`: `TransferCircuit` (`(LineageHeader, ()) -> LineageHeader`, enforces `asset` + `prev_commit` contiguity)
//! - `Index(3)`: `RoyaltyCircuit` (`(LineageHeader, ()) -> LineageHeader`, enforces `req && !paid == 0` + contiguity)
//! - `Index(4)`: `TicketCheckInCircuit` (`(LineageHeader, ()) -> LineageHeader`, Poseidon ticket nullifier + contiguity)
//! - `Index(5)`: `UpgradeCircuit` (`(LineageHeader, ()) -> LineageHeader`, `GAM1` state upgrade + contiguity)
//! - `Index(6)`: `OwnershipMerkleCircuit` (`() -> OwnershipHeader`, 4-level Poseidon Merkle inclusion + challenge binding)
//! - `Index(7)`: `IssuanceCapCircuit` (`() -> CapHeader`, 16-bit `Element::enforce_le::<16>` range check `1 <= idx <= cap`)
//! - `Index(8)`: `AttributeCircuit` (`() -> AttributeHeader`, Poseidon owner-leaf + trait + challenge binding)
//! - `Index(9)`: `MigrationCircuit` (`() -> MigrationHeader`, Stage I -> Stage II ZSA burn-nullifier binding)

use blake2b_simd::Params as Blake2bParams;
use ragu::drivers::emulator::{Emulator, Wireless};
use ragu::drivers::{Driver, DriverValue, LinearExpression};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::{Always, Maybe};
use ragu::pasta::{Fp as RaguFp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::poseidon::Sponge;
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::{Boolean, Element};
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::udon::field::Field as _;
use ragu::{
    Application, ApplicationBuilder, CompressedProof, Cycle, Proof, Result as RaguResult,
    WalletRank,
};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use zyoza_core::{
    AssetId, OwnershipProofRequest, OwnershipVerifyRequest, ProfileId, ProofBytes, ProofEngine,
    ZyozaError,
};

/// `[asset_fp, genesis_commit_fp, latest_commit_fp, lineage_acc_fp]`
const LINEAGE_SLOTS: usize = 4;
/// Payload slots plus Ragu's header suffix slot.
const HEADER_SIZE: usize = LINEAGE_SLOTS + 1;
/// Depth of the Poseidon Merkle tree used for collection ownership proofs (`2^4 = 16` leaves).
pub const MERKLE_DEPTH: usize = 4;

const SLOT_ASSET: usize = 0;
const SLOT_GENESIS: usize = 1;
const SLOT_LATEST: usize = 2;
const SLOT_ACC: usize = 3;

type ZyozaRaguApp = Application<'static, Pasta, WalletRank, HEADER_SIZE>;
type LineagePayload<'dr, D> = FixedVec<Element<'dr, D>, ConstLen<LINEAGE_SLOTS>>;

/// Ragu `Header` carrying `[asset_fp, genesis_commit_fp, latest_commit_fp, lineage_acc_fp]`.
pub struct LineageHeader;

impl Header<RaguFp> for LineageHeader {
    const SUFFIX: Suffix = Suffix::new(0);
    type OnlinePolyCommit = (Padding, Padding);
    type Data = [RaguFp; LINEAGE_SLOTS];
    type Output = Kind![RaguFp; FixedVec<Element<'_, _>, ConstLen<LINEAGE_SLOTS>>];

    fn encode<'dr, D: Driver<'dr, F = RaguFp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> RaguResult<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

fn lineage_header_value<'dr, D: Driver<'dr, F = RaguFp>>(
    out: &LineagePayload<'dr, D>,
) -> DriverValue<D, [RaguFp; LINEAGE_SLOTS]> {
    let mut acc: DriverValue<D, Vec<RaguFp>> = D::just(|| Vec::with_capacity(LINEAGE_SLOTS));
    for i in 0..LINEAGE_SLOTS {
        let v = out[i].value().map(|v| *v);
        acc = acc.and_then(|mut xs| {
            v.map(|v| {
                xs.push(v);
                xs
            })
        });
    }
    acc.map(|xs| core::array::from_fn(|i| xs[i]))
}

macro_rules! single_fp_header {
    ($name:ident, $suffix:expr) => {
        pub struct $name;

        impl Header<RaguFp> for $name {
            const SUFFIX: Suffix = Suffix::new($suffix);
            type OnlinePolyCommit = (Padding, Padding);
            type Data = RaguFp;
            type Output = Kind![RaguFp; Element<'_, _>];

            fn encode<'dr, D: Driver<'dr, F = RaguFp>, A: Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: DriverValue<D, Self::Data>,
            ) -> RaguResult<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, allocator, witness)
            }
        }
    };
}

single_fp_header!(OwnershipHeader, 1);
single_fp_header!(CapHeader, 2);
single_fp_header!(AttributeHeader, 3);
single_fp_header!(MigrationHeader, 4);

struct UnitStep;
impl Step<Pasta> for UnitStep {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        _: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
            ),
            D::unit(),
            D::unit(),
        ))
    }
}

#[derive(Clone, Copy)]
struct MintWitness {
    profile_fp: RaguFp,
    asset_fp: RaguFp,
    commit_fp: RaguFp,
    secret_fp: RaguFp,
}

struct MintCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for MintCircuit<'_> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = MintWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = LineageHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, LineageHeader, HS>,
        ),
        DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let tag = Element::constant(dr, RaguFp::from(1u64));
        let prof = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.profile_fp))?;
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let cmt = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.commit_fp))?;
        let sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.secret_fp))?;

        let mut sponge = Sponge::new(dr, self.poseidon);
        sponge.absorb(dr, &tag)?;
        sponge.absorb(dr, &prof)?;
        sponge.absorb(dr, &aid)?;
        sponge.absorb(dr, &cmt)?;
        sponge.absorb(dr, &sec)?;
        let acc = sponge.squeeze(dr)?;

        let out = FixedVec::new(vec![aid, cmt.clone(), cmt, acc])?;
        let data = lineage_header_value::<D>(&out);
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            data,
            D::unit(),
        ))
    }
}

#[derive(Clone, Copy)]
struct FoldCommonWitness {
    asset_fp: RaguFp,
    prev_commit_fp: RaguFp,
    next_commit_fp: RaguFp,
    profile_fp: RaguFp,
    secret_fp: RaguFp,
}

fn fold_lineage<'dr, D: Driver<'dr, F = RaguFp>, A: Allocator<'dr, D>>(
    dr: &mut D,
    alloc: &mut A,
    poseidon: &'dr <Pasta as ragu::Cycle>::CircuitPoseidon,
    tag_u64: u64,
    left_gadget: &LineagePayload<'dr, D>,
    common: DriverValue<D, FoldCommonWitness>,
    extra_absorb: Option<&Element<'dr, D>>,
) -> RaguResult<LineagePayload<'dr, D>> {
    let aid = Element::alloc(dr, alloc, common.as_ref().map(|w| w.asset_fp))?;
    let prev_cmt = Element::alloc(dr, alloc, common.as_ref().map(|w| w.prev_commit_fp))?;
    let next_cmt = Element::alloc(dr, alloc, common.as_ref().map(|w| w.next_commit_fp))?;
    let prof = Element::alloc(dr, alloc, common.as_ref().map(|w| w.profile_fp))?;
    let sec = Element::alloc(dr, alloc, common.as_ref().map(|w| w.secret_fp))?;

    left_gadget[SLOT_ASSET].sub(dr, &aid).enforce_zero(dr)?;
    left_gadget[SLOT_LATEST]
        .sub(dr, &prev_cmt)
        .enforce_zero(dr)?;

    let tag = Element::constant(dr, RaguFp::from(tag_u64));
    let mut sponge = Sponge::new(dr, poseidon);
    sponge.absorb(dr, &tag)?;
    sponge.absorb(dr, &left_gadget[SLOT_ACC])?;
    sponge.absorb(dr, &prof)?;
    sponge.absorb(dr, &next_cmt)?;
    sponge.absorb(dr, &sec)?;
    if let Some(extra) = extra_absorb {
        sponge.absorb(dr, extra)?;
    }
    let next_acc = sponge.squeeze(dr)?;

    FixedVec::new(vec![
        left_gadget[SLOT_ASSET].clone(),
        left_gadget[SLOT_GENESIS].clone(),
        next_cmt,
        next_acc,
    ])
}

struct TransferCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for TransferCircuit<'_> {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = FoldCommonWitness;
    type Aux<'source> = ();
    type Left = LineageHeader;
    type Right = ();
    type Output = LineageHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, LineageHeader, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, LineageHeader, HS>,
        ),
        DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let left_enc = Encoded::new(dr, alloc, left)?;
        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            2,
            left_enc.as_gadget(),
            witness,
            None,
        )?;
        let data = lineage_header_value::<D>(&out);
        Ok((
            (
                left_enc,
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            data,
            D::unit(),
        ))
    }
}

#[derive(Clone, Copy)]
struct RoyaltyWitness {
    common: FoldCommonWitness,
    royalty_required: bool,
    royalty_paid: bool,
}

struct RoyaltyCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for RoyaltyCircuit<'_> {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = RoyaltyWitness;
    type Aux<'source> = ();
    type Left = LineageHeader;
    type Right = ();
    type Output = LineageHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, LineageHeader, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, LineageHeader, HS>,
        ),
        DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let left_enc = Encoded::new(dr, alloc, left)?;

        let req = Boolean::alloc(dr, alloc, witness.as_ref().map(|w| w.royalty_required))?;
        let paid = Boolean::alloc(dr, alloc, witness.as_ref().map(|w| w.royalty_paid))?;
        let unpaid = paid.not(dr);
        let violation = req.and(dr, &unpaid)?;
        dr.enforce_zero(|lc| lc.add(violation.wire()))?;

        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            3,
            left_enc.as_gadget(),
            witness.map(|w| w.common),
            None,
        )?;
        let data = lineage_header_value::<D>(&out);
        Ok((
            (
                left_enc,
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            data,
            D::unit(),
        ))
    }
}

struct TicketCheckInCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for TicketCheckInCircuit<'_> {
    const INDEX: Index = Index::new(4);
    type Witness<'source> = FoldCommonWitness;
    type Aux<'source> = ();
    type Left = LineageHeader;
    type Right = ();
    type Output = LineageHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, LineageHeader, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, LineageHeader, HS>,
        ),
        DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let left_enc = Encoded::new(dr, alloc, left)?;

        let event_cmt = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.next_commit_fp))?;
        let holder_sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.secret_fp))?;
        let mut nf_sponge = Sponge::new(dr, self.poseidon);
        nf_sponge.absorb(dr, &holder_sec)?;
        nf_sponge.absorb(dr, &event_cmt)?;
        let ticket_nf = nf_sponge.squeeze(dr)?;

        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            4,
            left_enc.as_gadget(),
            witness,
            Some(&ticket_nf),
        )?;
        let data = lineage_header_value::<D>(&out);
        Ok((
            (
                left_enc,
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            data,
            D::unit(),
        ))
    }
}

struct UpgradeCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for UpgradeCircuit<'_> {
    const INDEX: Index = Index::new(5);
    type Witness<'source> = FoldCommonWitness;
    type Aux<'source> = ();
    type Left = LineageHeader;
    type Right = ();
    type Output = LineageHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, LineageHeader, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, LineageHeader, HS>,
        ),
        DriverValue<D, [RaguFp; LINEAGE_SLOTS]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let left_enc = Encoded::new(dr, alloc, left)?;
        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            5,
            left_enc.as_gadget(),
            witness,
            None,
        )?;
        let data = lineage_header_value::<D>(&out);
        Ok((
            (
                left_enc,
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            data,
            D::unit(),
        ))
    }
}

#[derive(Clone, Copy)]
struct OwnershipMerkleWitness {
    asset_fp: RaguFp,
    secret_fp: RaguFp,
    siblings: [(RaguFp, bool); MERKLE_DEPTH],
    challenge_fp: RaguFp,
}

struct OwnershipMerkleCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for OwnershipMerkleCircuit<'_> {
    const INDEX: Index = Index::new(6);
    type Witness<'source> = OwnershipMerkleWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = OwnershipHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, OwnershipHeader, HS>,
        ),
        DriverValue<D, RaguFp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.secret_fp))?;
        let chal = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.challenge_fp))?;

        let mut sp_tag = Sponge::new(dr, self.poseidon);
        sp_tag.absorb(dr, &sec)?;
        let owner_tag = sp_tag.squeeze(dr)?;

        let mut sp_leaf = Sponge::new(dr, self.poseidon);
        sp_leaf.absorb(dr, &aid)?;
        sp_leaf.absorb(dr, &owner_tag)?;
        let mut cur = sp_leaf.squeeze(dr)?;

        for level in 0..MERKLE_DEPTH {
            let sib = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.siblings[level].0))?;
            let sib_is_right =
                Boolean::alloc(dr, alloc, witness.as_ref().map(|w| w.siblings[level].1))?;
            let left_el = sib_is_right.conditional_select(dr, &sib, &cur)?;
            let right_el = sib_is_right.conditional_select(dr, &cur, &sib)?;

            let mut sp_node = Sponge::new(dr, self.poseidon);
            sp_node.absorb(dr, &left_el)?;
            sp_node.absorb(dr, &right_el)?;
            cur = sp_node.squeeze(dr)?;
        }

        let mut sp_out = Sponge::new(dr, self.poseidon);
        sp_out.absorb(dr, &cur)?;
        sp_out.absorb(dr, &chal)?;
        let out = sp_out.squeeze(dr)?;
        let out_val = out.value().map(|v| *v);

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            out_val,
            D::unit(),
        ))
    }
}

/// Ragu 16-bit supply-cap circuit (`Index 7`): proves `1 <= token_index <= max_supply <= 65,535`
/// using `Element::enforce_le::<16>` so neither `idx - 1` nor `max_supply - idx` can wrap modulo `p`.
#[derive(Clone, Copy)]
struct IssuanceCapWitness {
    idx_minus_1: u64,
    delta: u64,
}

struct IssuanceCapCircuit;

impl Step<Pasta> for IssuanceCapCircuit {
    const INDEX: Index = Index::new(7);
    type Witness<'source> = IssuanceCapWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = CapHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, CapHeader, HS>,
        ),
        DriverValue<D, RaguFp>,
        DriverValue<D, ()>,
    )> {
        let alloc = &mut Standard::new();
        let u16_max = RaguFp::from(u16::MAX as u64);
        let idx_m1 = Element::alloc(dr, alloc, witness.as_ref().map(|w| RaguFp::from(w.idx_minus_1)))?;
        let delta = Element::alloc(dr, alloc, witness.as_ref().map(|w| RaguFp::from(w.delta)))?;

        idx_m1.enforce_le::<16>(dr, alloc, u16_max)?;
        delta.enforce_le::<16>(dr, alloc, u16_max)?;

        let cap_out = idx_m1.add(dr, &Element::one()).add(dr, &delta);
        let out_val = cap_out.value().map(|v| *v);
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(cap_out),
            ),
            out_val,
            D::unit(),
        ))
    }
}

/// Ragu selective trait proof circuit (`Index 8`): binds `owner_leaf = Poseidon(asset, Poseidon(secret))`
/// to `(trait_fp, challenge_fp)` without revealing `asset` or `secret`.
#[derive(Clone, Copy)]
struct AttributeWitness {
    asset_fp: RaguFp,
    secret_fp: RaguFp,
    trait_fp: RaguFp,
    challenge_fp: RaguFp,
}

struct AttributeCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for AttributeCircuit<'_> {
    const INDEX: Index = Index::new(8);
    type Witness<'source> = AttributeWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = AttributeHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, AttributeHeader, HS>,
        ),
        DriverValue<D, RaguFp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.secret_fp))?;
        let tr = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.trait_fp))?;
        let ch = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.challenge_fp))?;

        let mut sp_tag = Sponge::new(dr, self.poseidon);
        sp_tag.absorb(dr, &sec)?;
        let owner_tag = sp_tag.squeeze(dr)?;

        let mut sp_leaf = Sponge::new(dr, self.poseidon);
        sp_leaf.absorb(dr, &aid)?;
        sp_leaf.absorb(dr, &owner_tag)?;
        let owner_leaf = sp_leaf.squeeze(dr)?;

        let mut sp_tr = Sponge::new(dr, self.poseidon);
        sp_tr.absorb(dr, &owner_leaf)?;
        sp_tr.absorb(dr, &tr)?;
        let bound_tr = sp_tr.squeeze(dr)?;

        let mut sp_out = Sponge::new(dr, self.poseidon);
        sp_out.absorb(dr, &bound_tr)?;
        sp_out.absorb(dr, &ch)?;
        let out = sp_out.squeeze(dr)?;
        let out_val = out.value().map(|v| *v);

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            out_val,
            D::unit(),
        ))
    }
}

/// Ragu Stage I -> Stage II ZSA burn-migration circuit (`Index 9`): proves non-zero owner secret
/// preimage for `burn_nf = Poseidon(asset, secret)` bound to `(asset, phase1_commitment)`.
#[derive(Clone, Copy)]
struct MigrationWitness {
    asset_fp: RaguFp,
    phase1_cmt_fp: RaguFp,
    secret_fp: RaguFp,
}

struct MigrationCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for MigrationCircuit<'_> {
    const INDEX: Index = Index::new(9);
    type Witness<'source> = MigrationWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = MigrationHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = RaguFp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> RaguResult<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, MigrationHeader, HS>,
        ),
        DriverValue<D, RaguFp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let p1 = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.phase1_cmt_fp))?;
        let sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.secret_fp))?;
        let _ = sec.clone().enforce_nonzero(dr)?;

        let mut sp_nf = Sponge::new(dr, self.poseidon);
        sp_nf.absorb(dr, &aid)?;
        sp_nf.absorb(dr, &sec)?;
        let burn_nf = sp_nf.squeeze(dr)?;

        let mut sp_pair = Sponge::new(dr, self.poseidon);
        sp_pair.absorb(dr, &aid)?;
        sp_pair.absorb(dr, &p1)?;
        let pair_fp = sp_pair.squeeze(dr)?;

        let mut sp_out = Sponge::new(dr, self.poseidon);
        sp_out.absorb(dr, &pair_fp)?;
        sp_out.absorb(dr, &burn_nf)?;
        let out = sp_out.squeeze(dr)?;
        let out_val = out.value().map(|v| *v);

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(out),
            ),
            out_val,
            D::unit(),
        ))
    }
}

struct CachedRagu {
    app: ZyozaRaguApp,
    unit_proof_bytes: Vec<u8>,
}

thread_local! {
    static RAGU_APP: CachedRagu = {
        let pasta = ragu::pcd::pasta::baked();
        let poseidon = Pasta::circuit_poseidon(pasta);
        let app = ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
            .register(UnitStep)
            .expect("register UnitStep")
            .register(MintCircuit { poseidon })
            .expect("register MintCircuit")
            .register(TransferCircuit { poseidon })
            .expect("register TransferCircuit")
            .register(RoyaltyCircuit { poseidon })
            .expect("register RoyaltyCircuit")
            .register(TicketCheckInCircuit { poseidon })
            .expect("register TicketCheckInCircuit")
            .register(UpgradeCircuit { poseidon })
            .expect("register UpgradeCircuit")
            .register(OwnershipMerkleCircuit { poseidon })
            .expect("register OwnershipMerkleCircuit")
            .register(IssuanceCapCircuit)
            .expect("register IssuanceCapCircuit")
            .register(AttributeCircuit { poseidon })
            .expect("register AttributeCircuit")
            .register(MigrationCircuit { poseidon })
            .expect("register MigrationCircuit")
            .finalize(pasta)
            .expect("finalize Ragu Application");

        let rng = &mut UnwrapErr(SysRng);
        let (unit_pcd, ()) = app.seed(rng, UnitStep, ()).expect("seed UnitStep");
        let unit_proof_bytes = unit_pcd.proof().to_bytes().expect("serialize unit proof");
        CachedRagu {
            app,
            unit_proof_bytes,
        }
    };
}

fn with_ragu<T>(f: impl FnOnce(&CachedRagu) -> T) -> T {
    RAGU_APP.with(f)
}

/// Returns the canonical byte size of a compressed Ragu proof at `WalletRank` (`7,168 bytes`).
pub fn compressed_proof_len() -> usize {
    CompressedProof::<Pasta>::encoded_len::<WalletRank>()
}

/// Computes `Poseidon(a)` natively using Ragu's `Emulator::execute()` so host & circuit match bit-for-bit.
pub fn poseidon_1(a: RaguFp) -> RaguFp {
    let pasta = ragu::pcd::pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let mut dr = Emulator::<Wireless<Always<()>, RaguFp>>::execute();
    let ea = Element::constant(&mut dr, a);
    let mut sp = Sponge::new(&mut dr, poseidon);
    sp.absorb(&mut dr, &ea).expect("absorb");
    let out = sp.squeeze(&mut dr).expect("squeeze");
    **out.value().snag()
}

/// Computes `Poseidon(a, b)` natively using Ragu's `Emulator::execute()`.
pub fn poseidon_2(a: RaguFp, b: RaguFp) -> RaguFp {
    let pasta = ragu::pcd::pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let mut dr = Emulator::<Wireless<Always<()>, RaguFp>>::execute();
    let ea = Element::constant(&mut dr, a);
    let eb = Element::constant(&mut dr, b);
    let mut sp = Sponge::new(&mut dr, poseidon);
    sp.absorb(&mut dr, &ea).expect("absorb");
    sp.absorb(&mut dr, &eb).expect("absorb");
    let out = sp.squeeze(&mut dr).expect("squeeze");
    **out.value().snag()
}

/// Maps arbitrary bytes deterministically into a canonical `RaguFp` element.
pub fn bytes_to_ragu_fp(personal: &[u8; 16], parts: &[&[u8]]) -> RaguFp {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(personal)
        .to_state();
    for p in parts {
        h.update(p);
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(h.finalize().as_bytes());
    b[31] &= 0x3f;
    RaguFp::from_bytes(b).expect("clamped < modulus")
}

/// Fixed-depth (`MERKLE_DEPTH = 4`, up to 16 assets) Poseidon Merkle collection registry
/// for genuine in-circuit `OwnershipMerkleCircuit` proofs.
#[derive(Debug, Clone)]
pub struct CollectionMerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl CollectionMerkleTree {
    /// Builds a collection tree from `(asset_id, owner_secret)` entries.
    pub fn from_holdings(entries: &[(AssetId, &[u8])]) -> Self {
        let mut leaves = Vec::with_capacity(1 << MERKLE_DEPTH);
        for (aid, sec) in entries {
            let aid_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&aid.0]);
            let sec_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[sec]);
            let tag = poseidon_1(sec_fp);
            let leaf = poseidon_2(aid_fp, tag);
            leaves.push(leaf.to_bytes());
        }
        while leaves.len() < (1 << MERKLE_DEPTH) {
            leaves.push(RaguFp::from(0u64).to_bytes());
        }
        leaves.truncate(1 << MERKLE_DEPTH);
        Self { leaves }
    }

    /// Computes the 32-byte Poseidon Merkle root of the collection.
    pub fn root(&self) -> [u8; 32] {
        let mut layer: Vec<RaguFp> = self
            .leaves
            .iter()
            .map(|b| RaguFp::from_bytes(*b).unwrap())
            .collect();
        for _ in 0..MERKLE_DEPTH {
            let mut next = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks_exact(2) {
                next.push(poseidon_2(pair[0], pair[1]));
            }
            layer = next;
        }
        layer[0].to_bytes()
    }

    /// Generates the 4-level `(sibling_bytes, sibling_is_right)` path for `index`.
    pub fn path(&self, mut index: usize) -> Vec<([u8; 32], bool)> {
        let mut layer: Vec<RaguFp> = self
            .leaves
            .iter()
            .map(|b| RaguFp::from_bytes(*b).unwrap())
            .collect();
        let mut out = Vec::with_capacity(MERKLE_DEPTH);
        for _ in 0..MERKLE_DEPTH {
            let is_right = index % 2 == 0;
            let sib = if is_right {
                layer[index + 1]
            } else {
                layer[index - 1]
            };
            out.push((sib.to_bytes(), is_right));
            let mut next = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks_exact(2) {
                next.push(poseidon_2(pair[0], pair[1]));
            }
            layer = next;
            index /= 2;
        }
        out
    }
}

/// Non-uniform PCD subcircuit step identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RaguStepKind {
    MintStep,
    TransferStep,
    RoyaltyStep,
    TicketCheckInStep,
    AttributeUpgradeStep,
}

impl RaguStepKind {
    /// Parses a strict step kind name, rejecting unknown strings.
    pub fn parse_strict(s: &str) -> Result<Self, ZyozaError> {
        match s {
            "MintStep" => Ok(Self::MintStep),
            "TransferStep" => Ok(Self::TransferStep),
            "RoyaltyStep" => Ok(Self::RoyaltyStep),
            "TicketCheckInStep" => Ok(Self::TicketCheckInStep),
            "AttributeUpgradeStep" => Ok(Self::AttributeUpgradeStep),
            other => Err(ZyozaError::Proof(format!("unknown RaguStepKind: {other}"))),
        }
    }
}

/// Witness for a single Ragu non-uniform PCD step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaguStepWitness {
    pub kind: RaguStepKind,
    pub profile_id: ProfileId,
    pub asset_id: AssetId,
    pub state_commitment: [u8; 32],
    pub secret_witness: Vec<u8>,
    pub royalty_required: bool,
    pub royalty_paid: bool,
}

/// Recursive Ragu PCD proof bundle carrying both the compressible recursive state
/// (`uncompressed_proof`) for further `fuse` hops and the succinct wire proof
/// (`compressed_proof`) verified in constant time via `Application::verify_compressed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaguPcdProof {
    pub asset_id: AssetId,
    pub genesis_commitment: [u8; 32],
    pub latest_commitment: [u8; 32],
    pub step_count: u64,
    pub last_step: RaguStepKind,
    pub last_profile: ProfileId,
    pub header_bytes: [u8; 32],
    pub uncompressed_proof: Vec<u8>,
    pub compressed_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaguAttributeProof {
    pub owner_leaf_bytes: [u8; 32],
    pub compressed_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaguMigrationProof {
    pub burn_nullifier_bytes: [u8; 32],
    pub compressed_proof: Vec<u8>,
}

/// Ragu 16-bit supply-cap prover/verifier (`1 <= token_index <= max_supply <= 65,535`).
#[derive(Debug, Default, Clone, Copy)]
pub struct IssuanceCapEngine;

impl IssuanceCapEngine {
    /// Generates a `7,168 B` Ragu `CompressedProof<Pasta>` proving `1 <= token_index <= max_supply`.
    pub fn prove_cap(&self, token_index: u64, max_supply: u64) -> Result<Vec<u8>, ZyozaError> {
        let (idx_minus_1, delta) = if token_index == 0 {
            (0, max_supply.min(u16::MAX as u64))
        } else {
            (
                (token_index - 1).min(u16::MAX as u64),
                max_supply.saturating_sub(token_index).min(u16::MAX as u64),
            )
        };
        with_ragu(|ctx| {
            let rng = &mut UnwrapErr(SysRng);
            let (pcd, ()) = ctx
                .app
                .seed(
                    rng,
                    IssuanceCapCircuit,
                    IssuanceCapWitness { idx_minus_1, delta },
                )
                .map_err(|e| ZyozaError::Proof(format!("ragu cap seed: {e:?}")))?;
            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu cap compress: {e:?}")))?;
            compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode cap proof: {e:?}")))
        })
    }

    /// Verifies a Ragu supply-cap proof against public `max_supply`.
    pub fn verify_cap(&self, max_supply: u64, proof: &[u8]) -> Result<bool, ZyozaError> {
        if proof.len() != compressed_proof_len() || max_supply > u16::MAX as u64 {
            return Ok(false);
        }
        with_ragu(|ctx| {
            let decoded = CompressedProof::<Pasta>::from_bytes(proof)
                .map_err(|e| ZyozaError::Proof(format!("decode cap proof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<CapHeader>(RaguFp::from(max_supply)))
                .map_err(|e| ZyozaError::Proof(format!("verify cap proof: {e:?}")))
        })
    }
}

/// Unified Ragu Non-Uniform Recursive PCD & ZK engine over Pasta (`WalletRank = R<13>`).
#[derive(Debug, Default, Clone, Copy)]
pub struct RaguPcdEngine;

impl RaguPcdEngine {
    /// Seeds (`prev == None`) or recursively fuses (`prev == Some(...)`) a non-uniform Ragu step.
    pub fn fold_step(
        &self,
        prev: Option<&RaguPcdProof>,
        step: &RaguStepWitness,
    ) -> Result<RaguPcdProof, ZyozaError> {
        if step.kind == RaguStepKind::RoyaltyStep && step.royalty_required && !step.royalty_paid {
            return Err(ZyozaError::Proof(
                "RoyaltyCircuit violation: required creator royalty unpaid".into(),
            ));
        }

        with_ragu(|ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

            let profile_fp = bytes_to_ragu_fp(b"ZYOZA-PROF-FP1__", &[&step.profile_id]);
            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&step.asset_id.0]);
            let commit_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&step.state_commitment]);
            let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[&step.secret_witness]);

            let (pcd, genesis_commitment, next_count) = match (prev, step.kind) {
                (None, RaguStepKind::MintStep) => {
                    let (seeded, ()) = ctx
                        .app
                        .seed(
                            rng,
                            MintCircuit { poseidon },
                            MintWitness {
                                profile_fp,
                                asset_fp,
                                commit_fp,
                                secret_fp,
                            },
                        )
                        .map_err(|e| ZyozaError::Proof(format!("ragu seed MintCircuit: {e:?}")))?;
                    (seeded, step.state_commitment, 1)
                }
                (None, other) => {
                    return Err(ZyozaError::Proof(format!(
                        "initial PCD step must be MintStep, got {other:?}"
                    )));
                }
                (Some(_), RaguStepKind::MintStep) => {
                    return Err(ZyozaError::Proof(
                        "cannot fold MintStep onto existing PCD lineage".into(),
                    ));
                }
                (Some(prior), kind) => {
                    if prior.asset_id != step.asset_id {
                        return Err(ZyozaError::Proof("PCD fold asset_id mismatch".into()));
                    }
                    let prior_gen_fp =
                        bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&prior.genesis_commitment]);
                    let prior_lat_fp =
                        bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&prior.latest_commitment]);
                    let prior_acc_fp = RaguFp::from_bytes(prior.header_bytes)
                        .ok_or_else(|| ZyozaError::Proof("invalid prior header Fp".into()))?;
                    let prior_data = [asset_fp, prior_gen_fp, prior_lat_fp, prior_acc_fp];

                    let left_pcd =
                        Proof::<Pasta, WalletRank>::from_bytes(&prior.uncompressed_proof)
                            .map_err(|e| ZyozaError::Proof(format!("decode left Proof: {e:?}")))?
                            .carry::<LineageHeader>(prior_data);
                    let unit_pcd = Proof::<Pasta, WalletRank>::from_bytes(&ctx.unit_proof_bytes)
                        .map_err(|e| ZyozaError::Proof(format!("decode unit Proof: {e:?}")))?
                        .carry::<()>(());

                    let common = FoldCommonWitness {
                        asset_fp,
                        prev_commit_fp: prior_lat_fp,
                        next_commit_fp: commit_fp,
                        profile_fp,
                        secret_fp,
                    };
                    let (fused, ()) = match kind {
                        RaguStepKind::TransferStep => ctx.app.fuse(
                            rng,
                            TransferCircuit { poseidon },
                            common,
                            left_pcd,
                            unit_pcd,
                        ),
                        RaguStepKind::RoyaltyStep => ctx.app.fuse(
                            rng,
                            RoyaltyCircuit { poseidon },
                            RoyaltyWitness {
                                common,
                                royalty_required: step.royalty_required,
                                royalty_paid: step.royalty_paid,
                            },
                            left_pcd,
                            unit_pcd,
                        ),
                        RaguStepKind::TicketCheckInStep => ctx.app.fuse(
                            rng,
                            TicketCheckInCircuit { poseidon },
                            common,
                            left_pcd,
                            unit_pcd,
                        ),
                        RaguStepKind::AttributeUpgradeStep => ctx.app.fuse(
                            rng,
                            UpgradeCircuit { poseidon },
                            common,
                            left_pcd,
                            unit_pcd,
                        ),
                        RaguStepKind::MintStep => unreachable!(),
                    }
                    .map_err(|e| ZyozaError::Proof(format!("ragu fuse({kind:?}): {e:?}")))?;

                    (fused, prior.genesis_commitment, prior.step_count + 1)
                }
            };

            let header_data = *pcd.data();
            let uncompressed_proof = pcd
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode uncompressed proof: {e:?}")))?;
            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu compress: {e:?}")))?;
            let compressed_proof = compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode compressed proof: {e:?}")))?;

            Ok(RaguPcdProof {
                asset_id: step.asset_id,
                genesis_commitment,
                latest_commitment: step.state_commitment,
                step_count: next_count,
                last_step: step.kind,
                last_profile: step.profile_id,
                header_bytes: header_data[SLOT_ACC].to_bytes(),
                uncompressed_proof,
                compressed_proof,
            })
        })
    }

    /// Cryptographically verifies a `RaguPcdProof`'s succinct compressed proof
    /// against `[asset_id, genesis_commitment, latest_commitment, header_bytes]`
    /// via `ragu::Application::verify_compressed`.
    pub fn verify_pcd(&self, proof: &RaguPcdProof) -> Result<bool, ZyozaError> {
        if proof.compressed_proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        with_ragu(|ctx| {
            let Some(acc_fp) = RaguFp::from_bytes(proof.header_bytes) else {
                return Ok(false);
            };
            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&proof.asset_id.0]);
            let gen_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&proof.genesis_commitment]);
            let lat_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&proof.latest_commitment]);
            let data = [asset_fp, gen_fp, lat_fp, acc_fp];

            let decoded = CompressedProof::<Pasta>::from_bytes(&proof.compressed_proof)
                .map_err(|e| ZyozaError::Proof(format!("decode CompressedProof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<LineageHeader>(data))
                .map_err(|e| ZyozaError::Proof(format!("ragu verify_compressed: {e:?}")))
        })
    }

    /// Generates a genuine Ragu Poseidon-Merkle ZK ownership proof bound to `(collection_root, challenge)`.
    pub fn prove_merkle_ownership(
        &self,
        req: &OwnershipProofRequest,
    ) -> Result<ProofBytes, ZyozaError> {
        if req.merkle_siblings.len() != MERKLE_DEPTH {
            return Err(ZyozaError::Proof(format!(
                "expected {MERKLE_DEPTH} merkle_siblings, got {}",
                req.merkle_siblings.len()
            )));
        }
        with_ragu(|ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&req.asset_id.0]);
            let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[&req.secret_witness]);
            let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&req.challenge]);

            let mut siblings = [(RaguFp::from(0u64), true); MERKLE_DEPTH];
            for (i, (sib_bytes, is_right)) in req.merkle_siblings.iter().enumerate() {
                let sib_fp = RaguFp::from_bytes(*sib_bytes)
                    .ok_or_else(|| ZyozaError::Proof("non-canonical Merkle sibling Fp".into()))?;
                siblings[i] = (sib_fp, *is_right);
            }

            let (pcd, ()) = ctx
                .app
                .seed(
                    rng,
                    OwnershipMerkleCircuit { poseidon },
                    OwnershipMerkleWitness {
                        asset_fp,
                        secret_fp,
                        siblings,
                        challenge_fp,
                    },
                )
                .map_err(|e| ZyozaError::Proof(format!("ragu ownership seed: {e:?}")))?;

            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu ownership compress: {e:?}")))?;
            compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode ownership proof: {e:?}")))
        })
    }

    /// Verifies a Ragu Poseidon-Merkle ZK ownership proof against `(collection_root, challenge)`.
    pub fn verify_merkle_ownership(
        &self,
        req: &OwnershipVerifyRequest,
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        if proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        with_ragu(|ctx| {
            let Some(root_fp) = RaguFp::from_bytes(req.collection_root) else {
                return Ok(false);
            };
            let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&req.challenge]);
            let expected_header = poseidon_2(root_fp, challenge_fp);

            let decoded = CompressedProof::<Pasta>::from_bytes(proof)
                .map_err(|e| ZyozaError::Proof(format!("decode ownership CompressedProof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<OwnershipHeader>(expected_header))
                .map_err(|e| ZyozaError::Proof(format!("verify ownership: {e:?}")))
        })
    }

    /// Generates a Ragu `AttributeCircuit` proof binding `owner_leaf` to `(trait_key, trait_val, challenge)`.
    pub fn prove_attribute(
        &self,
        asset_id: &AssetId,
        trait_key: &str,
        trait_val: &str,
        secret_witness: &[u8],
        challenge: [u8; 32],
    ) -> Result<ProofBytes, ZyozaError> {
        with_ragu(|ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
            let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[secret_witness]);
            let trait_fp = bytes_to_ragu_fp(
                b"ZYOZA-TRAIT-FP1_",
                &[trait_key.as_bytes(), b":", trait_val.as_bytes()],
            );
            let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&challenge]);
            let owner_leaf = poseidon_2(asset_fp, poseidon_1(secret_fp));

            let (pcd, ()) = ctx
                .app
                .seed(
                    rng,
                    AttributeCircuit { poseidon },
                    AttributeWitness {
                        asset_fp,
                        secret_fp,
                        trait_fp,
                        challenge_fp,
                    },
                )
                .map_err(|e| ZyozaError::Proof(format!("ragu attribute seed: {e:?}")))?;
            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu attribute compress: {e:?}")))?;
            let compressed_proof = compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode attribute proof: {e:?}")))?;

            serde_json::to_vec(&RaguAttributeProof {
                owner_leaf_bytes: owner_leaf.to_bytes(),
                compressed_proof,
            })
            .map_err(|e| ZyozaError::Proof(format!("serialize attribute proof: {e}")))
        })
    }

    /// Verifies a Ragu `AttributeCircuit` proof against `(trait_key, trait_val, challenge)`.
    pub fn verify_attribute(
        &self,
        trait_key: &str,
        trait_val: &str,
        challenge: [u8; 32],
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        let parsed: RaguAttributeProof = serde_json::from_slice(proof)
            .map_err(|e| ZyozaError::Proof(format!("parse attribute proof: {e}")))?;
        if parsed.compressed_proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        with_ragu(|ctx| {
            let Some(owner_leaf) = RaguFp::from_bytes(parsed.owner_leaf_bytes) else {
                return Ok(false);
            };
            let trait_fp = bytes_to_ragu_fp(
                b"ZYOZA-TRAIT-FP1_",
                &[trait_key.as_bytes(), b":", trait_val.as_bytes()],
            );
            let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&challenge]);
            let expected = poseidon_2(poseidon_2(owner_leaf, trait_fp), challenge_fp);

            let decoded = CompressedProof::<Pasta>::from_bytes(&parsed.compressed_proof)
                .map_err(|e| ZyozaError::Proof(format!("decode attribute proof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<AttributeHeader>(expected))
                .map_err(|e| ZyozaError::Proof(format!("verify attribute proof: {e:?}")))
        })
    }

    /// Generates a Ragu `MigrationCircuit` proof for Stage I burn -> Stage II ZSA crystallization.
    pub fn prove_migration(
        &self,
        asset_id: &AssetId,
        phase1_commitment: [u8; 32],
        secret_witness: &[u8],
    ) -> Result<ProofBytes, ZyozaError> {
        with_ragu(|ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
            let phase1_cmt_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&phase1_commitment]);
            let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[secret_witness]);
            let burn_nf = poseidon_2(asset_fp, secret_fp);

            let (pcd, ()) = ctx
                .app
                .seed(
                    rng,
                    MigrationCircuit { poseidon },
                    MigrationWitness {
                        asset_fp,
                        phase1_cmt_fp,
                        secret_fp,
                    },
                )
                .map_err(|e| ZyozaError::Proof(format!("ragu migration seed: {e:?}")))?;
            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu migration compress: {e:?}")))?;
            let compressed_proof = compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode migration proof: {e:?}")))?;

            serde_json::to_vec(&RaguMigrationProof {
                burn_nullifier_bytes: burn_nf.to_bytes(),
                compressed_proof,
            })
            .map_err(|e| ZyozaError::Proof(format!("serialize migration proof: {e}")))
        })
    }

    /// Verifies a Ragu `MigrationCircuit` proof against `(asset_id, phase1_commitment)`.
    pub fn verify_migration(
        &self,
        asset_id: &AssetId,
        phase1_commitment: [u8; 32],
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        let parsed: RaguMigrationProof = serde_json::from_slice(proof)
            .map_err(|e| ZyozaError::Proof(format!("parse migration proof: {e}")))?;
        if parsed.compressed_proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        with_ragu(|ctx| {
            let Some(burn_nf) = RaguFp::from_bytes(parsed.burn_nullifier_bytes) else {
                return Ok(false);
            };
            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
            let phase1_cmt_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&phase1_commitment]);
            let expected = poseidon_2(poseidon_2(asset_fp, phase1_cmt_fp), burn_nf);

            let decoded = CompressedProof::<Pasta>::from_bytes(&parsed.compressed_proof)
                .map_err(|e| ZyozaError::Proof(format!("decode migration proof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<MigrationHeader>(expected))
                .map_err(|e| ZyozaError::Proof(format!("verify migration proof: {e:?}")))
        })
    }
}

impl ProofEngine for RaguPcdEngine {
    fn prove_ownership(&self, req: &OwnershipProofRequest) -> Result<ProofBytes, ZyozaError> {
        self.prove_merkle_ownership(req)
    }

    fn verify_ownership(
        &self,
        req: &OwnershipVerifyRequest,
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        self.verify_merkle_ownership(req, proof)
    }

    fn prove_transition(
        &self,
        prev_proof: Option<&[u8]>,
        step_witness: &[u8],
    ) -> Result<ProofBytes, ZyozaError> {
        let prev = match prev_proof {
            Some(b) => Some(
                serde_json::from_slice::<RaguPcdProof>(b)
                    .map_err(|e| ZyozaError::Proof(format!("parse prev pcd: {e}")))?,
            ),
            None => None,
        };
        let step: RaguStepWitness = serde_json::from_slice(step_witness)
            .map_err(|e| ZyozaError::Proof(format!("parse step witness: {e}")))?;
        let folded = self.fold_step(prev.as_ref(), &step)?;
        serde_json::to_vec(&folded)
            .map_err(|e| ZyozaError::Proof(format!("serialize pcd: {e}")))
    }

    fn verify_transition(&self, proof: &[u8], _public_inputs: &[u8]) -> Result<bool, ZyozaError> {
        let pcd: RaguPcdProof = serde_json::from_slice(proof)
            .map_err(|e| ZyozaError::Proof(format!("parse pcd: {e}")))?;
        self.verify_pcd(&pcd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_ragu_recursive_multi_profile_pcd_and_royalty_rejection() {
        let engine = RaguPcdEngine;
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:ragu:real:1");

        let t_init = std::time::Instant::now();
        with_ragu(|_| {});
        let init_ms = t_init.elapsed().as_millis();

        let t_seed = std::time::Instant::now();
        let pcd1 = engine
            .fold_step(
                None,
                &RaguStepWitness {
                    kind: RaguStepKind::MintStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x01; 32],
                    secret_witness: b"creator-sk".to_vec(),
                    royalty_required: false,
                    royalty_paid: false,
                },
            )
            .unwrap();
        let seed_ms = t_seed.elapsed().as_millis();
        assert!(engine.verify_pcd(&pcd1).unwrap());
        let len_1 = pcd1.compressed_proof.len();
        assert_eq!(len_1, compressed_proof_len());

        // Unpaid required royalty is rejected both natively and by the in-circuit Boolean gate!
        assert!(engine
            .fold_step(
                Some(&pcd1),
                &RaguStepWitness {
                    kind: RaguStepKind::RoyaltyStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x02; 32],
                    secret_witness: b"seller-sk".to_vec(),
                    royalty_required: true,
                    royalty_paid: false,
                },
            )
            .is_err());

        with_ragu(|ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);
            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
            let gen_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&pcd1.genesis_commitment]);
            let acc_fp = RaguFp::from_bytes(pcd1.header_bytes).unwrap();
            let left_pcd = Proof::<Pasta, WalletRank>::from_bytes(&pcd1.uncompressed_proof)
                .unwrap()
                .carry::<LineageHeader>([asset_fp, gen_fp, gen_fp, acc_fp]);
            let unit_pcd = Proof::<Pasta, WalletRank>::from_bytes(&ctx.unit_proof_bytes)
                .unwrap()
                .carry::<()>(());
            let (forged_pcd, ()) = ctx
                .app
                .fuse(
                    rng,
                    RoyaltyCircuit { poseidon },
                    RoyaltyWitness {
                        common: FoldCommonWitness {
                            asset_fp,
                            prev_commit_fp: gen_fp,
                            next_commit_fp: bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&[0x02; 32]]),
                            profile_fp: bytes_to_ragu_fp(b"ZYOZA-PROF-FP1__", &[b"NFT1"]),
                            secret_fp: bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[b"seller-sk"]),
                        },
                        royalty_required: true,
                        royalty_paid: false,
                    },
                    left_pcd,
                    unit_pcd,
                )
                .unwrap();
            let compressed_forged = ctx.app.compress(&forged_pcd, rng).unwrap();
            assert!(!ctx.app.verify_compressed(&compressed_forged).unwrap());
        });

        let pcd2 = engine
            .fold_step(
                Some(&pcd1),
                &RaguStepWitness {
                    kind: RaguStepKind::RoyaltyStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x02; 32],
                    secret_witness: b"seller-sk".to_vec(),
                    royalty_required: true,
                    royalty_paid: true,
                },
            )
            .unwrap();
        let pcd3 = engine
            .fold_step(
                Some(&pcd2),
                &RaguStepWitness {
                    kind: RaguStepKind::TicketCheckInStep,
                    profile_id: *b"TKT1",
                    asset_id,
                    state_commitment: [0x03; 32],
                    secret_witness: b"venue-sk".to_vec(),
                    royalty_required: false,
                    royalty_paid: false,
                },
            )
            .unwrap();
        let t_fold = std::time::Instant::now();
        let pcd4 = engine
            .fold_step(
                Some(&pcd3),
                &RaguStepWitness {
                    kind: RaguStepKind::AttributeUpgradeStep,
                    profile_id: *b"GAM1",
                    asset_id,
                    state_commitment: [0x04; 32],
                    secret_witness: b"player-sk".to_vec(),
                    royalty_required: false,
                    royalty_paid: false,
                },
            )
            .unwrap();
        let fold_ms = t_fold.elapsed().as_millis();

        let t_ver = std::time::Instant::now();
        assert!(engine.verify_pcd(&pcd4).unwrap());
        let ver_ms = t_ver.elapsed().as_millis();
        println!(
            "[Ragu Multicore Benchmark] proof={}B init={}ms warm_seed={}ms warm_fold={}ms verify={}ms",
            len_1, init_ms, seed_ms, fold_ms, ver_ms
        );
        assert_eq!(pcd4.step_count, 4);
        assert_eq!(pcd4.compressed_proof.len(), len_1);

        let mut tampered_latest = pcd4.clone();
        tampered_latest.latest_commitment = [0x99; 32];
        assert!(!engine.verify_pcd(&tampered_latest).unwrap());
        assert!(RaguStepKind::parse_strict("Bogus").is_err());
    }

    #[test]
    fn ragu_merkle_ownership_attribute_migration_and_cap_proofs() {
        let engine = RaguPcdEngine;
        let a1 = AssetId::derive(&[0x01; 32], b"zyoza:col:1");
        let a2 = AssetId::derive(&[0x01; 32], b"zyoza:col:2");
        let unlisted = AssetId::derive(&[0x01; 32], b"zyoza:col:999");

        let tree = CollectionMerkleTree::from_holdings(&[
            (a1, b"alice-real-secret"),
            (a2, b"bob-real-secret"),
        ]);
        let root = tree.root();
        let challenge = [0x77; 32];

        // 1. Merkle ownership: valid passes, wrong secret & unlisted asset rejected
        let valid_proof = engine
            .prove_merkle_ownership(&OwnershipProofRequest {
                asset_id: a1,
                collection_root: root,
                merkle_siblings: tree.path(0),
                secret_witness: b"alice-real-secret".to_vec(),
                challenge,
            })
            .unwrap();
        assert!(engine
            .verify_merkle_ownership(
                &OwnershipVerifyRequest {
                    collection_root: root,
                    challenge,
                },
                &valid_proof
            )
            .unwrap());

        let wrong_secret_proof = engine
            .prove_merkle_ownership(&OwnershipProofRequest {
                asset_id: a1,
                collection_root: root,
                merkle_siblings: tree.path(0),
                secret_witness: b"attacker-random-secret".to_vec(),
                challenge,
            })
            .unwrap();
        assert!(!engine
            .verify_merkle_ownership(
                &OwnershipVerifyRequest {
                    collection_root: root,
                    challenge,
                },
                &wrong_secret_proof
            )
            .unwrap());

        let unlisted_proof = engine
            .prove_merkle_ownership(&OwnershipProofRequest {
                asset_id: unlisted,
                collection_root: root,
                merkle_siblings: tree.path(0),
                secret_witness: b"alice-real-secret".to_vec(),
                challenge,
            })
            .unwrap();
        assert!(!engine
            .verify_merkle_ownership(
                &OwnershipVerifyRequest {
                    collection_root: root,
                    challenge,
                },
                &unlisted_proof
            )
            .unwrap());

        // 2. Selective attribute proof
        let attr_proof = engine
            .prove_attribute(&a1, "shades", "venetian", b"alice-real-secret", challenge)
            .unwrap();
        assert!(engine
            .verify_attribute("shades", "venetian", challenge, &attr_proof)
            .unwrap());
        assert!(!engine
            .verify_attribute("shades", "mesh", challenge, &attr_proof)
            .unwrap());

        // 3. Stage I -> Stage II ZSA burn-migration proof
        let mig_proof = engine
            .prove_migration(&a1, [0x44; 32], b"alice-real-secret")
            .unwrap();
        assert!(engine.verify_migration(&a1, [0x44; 32], &mig_proof).unwrap());
        assert!(!engine.verify_migration(&a1, [0x55; 32], &mig_proof).unwrap());

        // 4. Ragu 16-bit supply-cap range proof (`1 <= idx <= max_supply`)
        let cap_engine = IssuanceCapEngine;
        let cap_ok = cap_engine.prove_cap(42, 100).unwrap();
        assert!(cap_engine.verify_cap(100, &cap_ok).unwrap());

        let cap_over = cap_engine.prove_cap(101, 100).unwrap();
        assert!(!cap_engine.verify_cap(100, &cap_over).unwrap());

        let cap_zero = cap_engine.prove_cap(0, 100).unwrap();
        assert!(!cap_engine.verify_cap(100, &cap_zero).unwrap());
    }
}
