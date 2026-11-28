//! Unified `tachyon-zcash/ragu` Non-Uniform Proof-Carrying Data (PCD) & ZK engine over Pasta.
//!
//! Every zero-knowledge proof in Zyoza executes inside a single unified
//! `ragu::Application<'static, Pasta, WalletRank, 12>` with 10 registered `Step<Pasta>` subcircuits,
//! hosted on a **single dedicated prover OS thread** (so baked Pasta synthesis tables are built
//! at most once per process while Ragu's `multicore` Rayon pool parallelizes MSMs/FFTs across cores).
//!
//! ### Privacy Caveat (Upstream `tachyon-zcash/ragu`)
//! While a terminal `CompressedProof<Pasta>` hides private witness wires from third-party verifiers,
//! continuing a recursive lineage (`Application::fuse`) requires passing the uncompressed
//! `Proof<Pasta, WalletRank>` to the next holder. Per Ragu's upstream documentation, uncompressed
//! proofs are **not yet zero-knowledge** and `rerandomize` is **not yet unlinkable** across hops.

use blake2b_simd::Params as Blake2bParams;
use ragu::drivers::emulator::{Emulator, Wireless};
use ragu::drivers::{Driver, DriverValue};
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

/// 10 verified public field elements in `LineageHeader`:
/// `[asset, genesis_cmt, latest_cmt, owner_tag, step_count, last_kind, last_profile, royalty_req, creator_tag, event_nf]`
pub const LINEAGE_SLOTS: usize = 10;
const HEADER_SIZE: usize = 12;
/// Depth of Poseidon Merkle trees used for collection ownership and committed trait proofs (`2^4 = 16` leaves).
pub const MERKLE_DEPTH: usize = 4;

pub const SLOT_ASSET: usize = 0;
pub const SLOT_GENESIS: usize = 1;
pub const SLOT_LATEST: usize = 2;
pub const SLOT_OWNER_TAG: usize = 3;
pub const SLOT_STEP_COUNT: usize = 4;
pub const SLOT_LAST_KIND: usize = 5;
pub const SLOT_LAST_PROF: usize = 6;
pub const SLOT_ROYALTY_REQ: usize = 7;
pub const SLOT_CREATOR_TAG: usize = 8;
pub const SLOT_EVENT_NF: usize = 9;

type ZyozaRaguApp = Application<'static, Pasta, WalletRank, HEADER_SIZE>;
type FixedPayload<'dr, D, const N: usize> = FixedVec<Element<'dr, D>, ConstLen<N>>;

macro_rules! array_fp_header {
    ($name:ident, $suffix:expr, $slots:expr) => {
        pub struct $name;

        impl Header<RaguFp> for $name {
            const SUFFIX: Suffix = Suffix::new($suffix);
            type OnlinePolyCommit = (Padding, Padding);
            type Data = [RaguFp; $slots];
            type Output = Kind![RaguFp; FixedVec<Element<'_, _>, ConstLen<$slots>>];

            fn encode<'dr, D: Driver<'dr, F = RaguFp>, A: Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: DriverValue<D, Self::Data>,
            ) -> RaguResult<Bound<'dr, D, Self::Output>> {
                FixedVec::try_from_fn(|i| {
                    Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i]))
                })
            }
        }
    };
}

fn fixed_header_value<'dr, D: Driver<'dr, F = RaguFp>, const N: usize>(
    out: &FixedPayload<'dr, D, N>,
) -> DriverValue<D, [RaguFp; N]> {
    let mut acc: DriverValue<D, Vec<RaguFp>> = D::just(|| Vec::with_capacity(N));
    for i in 0..N {
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

array_fp_header!(LineageHeader, 0, LINEAGE_SLOTS);
array_fp_header!(OwnershipHeader, 1, 3);
array_fp_header!(CapHeader, 2, 4);
array_fp_header!(AttributeHeader, 3, 4);
array_fp_header!(MigrationHeader, 4, 4);

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
    owner_secret_fp: RaguFp,
    royalty_required: bool,
    creator_tag_fp: RaguFp,
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
        let prof = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.profile_fp))?;
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let cmt = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.commit_fp))?;
        let sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.owner_secret_fp))?;
        let roy_bool = Boolean::alloc(dr, alloc, witness.as_ref().map(|w| w.royalty_required))?;
        let zero_el = Element::zero(dr);
        let roy_el = roy_bool.conditional_select(dr, &zero_el, &Element::one())?;
        let creator_tag = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.creator_tag_fp))?;

        let mut sp = Sponge::new(dr, self.poseidon);
        sp.absorb(dr, &sec)?;
        let owner_tag = sp.squeeze(dr)?;

        let zero_nf = Element::zero(dr);
        let out = FixedVec::new(vec![
            aid,
            cmt.clone(),
            cmt,
            owner_tag,
            Element::one(),
            Element::constant(dr, RaguFp::from(1u64)),
            prof,
            roy_el,
            creator_tag,
            zero_nf,
        ])?;
        let data = fixed_header_value::<D, LINEAGE_SLOTS>(&out);
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
    current_owner_secret_fp: RaguFp,
    next_owner_tag_fp: RaguFp,
}

/// Shared recursive verifier check:
/// 1. `left[SLOT_ASSET] == witness.asset_fp`
/// 2. `left[SLOT_LATEST] == witness.prev_commit_fp`
/// 3. `left[SLOT_OWNER_TAG] == Poseidon(witness.current_owner_secret_fp)` (owner authorization!)
/// 4. Increments `step_count`, records `last_kind` + `last_profile`, preserves sticky `royalty_req` & `creator_tag`.
#[allow(clippy::too_many_arguments)]
fn fold_lineage<'dr, D: Driver<'dr, F = RaguFp>, A: Allocator<'dr, D>>(
    dr: &mut D,
    alloc: &mut A,
    poseidon: &'dr <Pasta as ragu::Cycle>::CircuitPoseidon,
    kind_u64: u64,
    left_gadget: &FixedPayload<'dr, D, LINEAGE_SLOTS>,
    common: DriverValue<D, FoldCommonWitness>,
    event_nf: Element<'dr, D>,
) -> RaguResult<FixedPayload<'dr, D, LINEAGE_SLOTS>> {
    let aid = Element::alloc(dr, alloc, common.as_ref().map(|w| w.asset_fp))?;
    let prev_cmt = Element::alloc(dr, alloc, common.as_ref().map(|w| w.prev_commit_fp))?;
    let next_cmt = Element::alloc(dr, alloc, common.as_ref().map(|w| w.next_commit_fp))?;
    let prof = Element::alloc(dr, alloc, common.as_ref().map(|w| w.profile_fp))?;
    let cur_sec = Element::alloc(dr, alloc, common.as_ref().map(|w| w.current_owner_secret_fp))?;
    let next_owner_tag = Element::alloc(dr, alloc, common.as_ref().map(|w| w.next_owner_tag_fp))?;

    // 1. Asset identity invariance
    left_gadget[SLOT_ASSET].sub(dr, &aid).enforce_zero(dr)?;
    // 2. Contiguous state-commitment chain
    left_gadget[SLOT_LATEST]
        .sub(dr, &prev_cmt)
        .enforce_zero(dr)?;
    // 3. Current owner secret preimage check!
    let mut sp = Sponge::new(dr, poseidon);
    sp.absorb(dr, &cur_sec)?;
    let cur_owner_tag = sp.squeeze(dr)?;
    left_gadget[SLOT_OWNER_TAG]
        .sub(dr, &cur_owner_tag)
        .enforce_zero(dr)?;

    let next_count = left_gadget[SLOT_STEP_COUNT].add(dr, &Element::one());
    let kind_el = Element::constant(dr, RaguFp::from(kind_u64));

    FixedVec::new(vec![
        left_gadget[SLOT_ASSET].clone(),
        left_gadget[SLOT_GENESIS].clone(),
        next_cmt,
        next_owner_tag,
        next_count,
        kind_el,
        prof,
        left_gadget[SLOT_ROYALTY_REQ].clone(),
        left_gadget[SLOT_CREATOR_TAG].clone(),
        event_nf,
    ])
}

/// Non-royalty transfer (`Index 2`): enforces `left[SLOT_ROYALTY_REQ] == 0` so royalty-bearing
/// collections CANNOT bypass `RoyaltyCircuit`!
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
        let left_gad: &FixedPayload<'dr, D, LINEAGE_SLOTS> = left_enc.as_gadget();
        // Reject TransferCircuit if genesis policy marked royalty_required == 1!
        left_gad[SLOT_ROYALTY_REQ].enforce_zero(dr)?;

        let zero_nf = Element::zero(dr);
        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            2,
            left_gad,
            witness,
            zero_nf,
        )?;
        let data = fixed_header_value::<D, LINEAGE_SLOTS>(&out);
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
    /// Preimage of `SLOT_CREATOR_TAG` acknowledging creator/escrow royalty settlement.
    creator_ack_secret_fp: RaguFp,
}

/// Royalty-enforced transfer (`Index 3`): when `left[SLOT_ROYALTY_REQ] == 1`, enforces
/// `Poseidon(creator_ack_secret_fp) == left[SLOT_CREATOR_TAG]`. A seller cannot unilaterally
/// flip a boolean to bypass the creator's receipt preimage.
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
        let left_gad: &FixedPayload<'dr, D, LINEAGE_SLOTS> = left_enc.as_gadget();

        let ack_sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.creator_ack_secret_fp))?;
        let mut sp = Sponge::new(dr, self.poseidon);
        sp.absorb(dr, &ack_sec)?;
        let ack_tag = sp.squeeze(dr)?;

        // Enforce: left[SLOT_ROYALTY_REQ] * (ack_tag - left[SLOT_CREATOR_TAG]) == 0
        let diff = ack_tag.sub(dr, &left_gad[SLOT_CREATOR_TAG]);
        let gated_diff = left_gad[SLOT_ROYALTY_REQ].mul(dr, &diff)?;
        gated_diff.enforce_zero(dr)?;

        let zero_nf = Element::zero(dr);
        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            3,
            left_gad,
            witness.map(|w| w.common),
            zero_nf,
        )?;
        let data = fixed_header_value::<D, LINEAGE_SLOTS>(&out);
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
struct TicketWitness {
    common: FoldCommonWitness,
    event_id_fp: RaguFp,
}

/// Ticket check-in step (`Index 4`): derives `event_nf = Poseidon(asset, event_id)` in-circuit
/// from the lineage's own asset slot and exposes it in `SLOT_EVENT_NF`.
///
/// The nullifier depends only on the object and the event. It does not depend on the holder or
/// on the next state commitment, so the same ticket yields the same nullifier however often it
/// is checked in and whoever holds it, and a gate that records nullifiers refuses the repeat.
/// The gate must also check the nullifier is the one for its own event
/// (`derive_ticket_event_nullifier`). Authority to check in comes from the owner check that
/// every fold performs.
struct TicketCheckInCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for TicketCheckInCircuit<'_> {
    const INDEX: Index = Index::new(4);
    type Witness<'source> = TicketWitness;
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

        // Use the asset the lineage itself carries, not a second allocation of it.
        let left_slots: &FixedPayload<'dr, D, LINEAGE_SLOTS> = left_enc.as_gadget();
        let aid = left_slots[SLOT_ASSET].clone();
        let event_id = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.event_id_fp))?;

        let mut sp = Sponge::new(dr, self.poseidon);
        sp.absorb(dr, &aid)?;
        sp.absorb(dr, &event_id)?;
        let ticket_nf = sp.squeeze(dr)?;

        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            4,
            left_enc.as_gadget(),
            witness.map(|w| w.common),
            ticket_nf,
        )?;
        let data = fixed_header_value::<D, LINEAGE_SLOTS>(&out);
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
        let zero_nf = Element::zero(dr);
        let out = fold_lineage(
            dr,
            alloc,
            self.poseidon,
            5,
            left_enc.as_gadget(),
            witness,
            zero_nf,
        )?;
        let data = fixed_header_value::<D, LINEAGE_SLOTS>(&out);
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
    state_root_fp: RaguFp,
    secret_fp: RaguFp,
    siblings: [(RaguFp, bool); MERKLE_DEPTH],
    challenge_fp: RaguFp,
}

/// Ragu circuit (`Index 6`) proving:
/// 1. `owner_tag = Poseidon(secret)`
/// 2. `obj_bind = Poseidon(asset_id, state_root)`
/// 3. `leaf = Poseidon(obj_bind, owner_tag)` resolves via 4-level Merkle path to `collection_root`
/// 4. Public `OwnershipHeader = [collection_root, state_root, challenge]`
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
        DriverValue<D, [RaguFp; 3]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let st_root = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.state_root_fp))?;
        let sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.secret_fp))?;
        let chal = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.challenge_fp))?;

        let mut sp_tag = Sponge::new(dr, self.poseidon);
        sp_tag.absorb(dr, &sec)?;
        let owner_tag = sp_tag.squeeze(dr)?;

        let mut sp_obj = Sponge::new(dr, self.poseidon);
        sp_obj.absorb(dr, &aid)?;
        sp_obj.absorb(dr, &st_root)?;
        let obj_bind = sp_obj.squeeze(dr)?;

        let mut sp_leaf = Sponge::new(dr, self.poseidon);
        sp_leaf.absorb(dr, &obj_bind)?;
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

        let out = FixedVec::new(vec![cur, st_root, chal])?;
        let data = fixed_header_value::<D, 3>(&out);
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

/// Ragu 16-bit supply-cap circuit (`Index 7`): binds `slot_commitment = Poseidon(Poseidon(col_id, asset), Poseidon(idx, blinding))`
/// to public `[col_id, asset, slot_commitment, max_supply]` while proving `1 <= idx <= max_supply <= 65,535`.
#[derive(Clone, Copy)]
struct IssuanceCapWitness {
    col_id_fp: RaguFp,
    asset_fp: RaguFp,
    idx_minus_1: u64,
    delta: u64,
    blinding_fp: RaguFp,
}

struct IssuanceCapCircuit<'params> {
    poseidon: &'params <Pasta as ragu::Cycle>::CircuitPoseidon,
}

impl Step<Pasta> for IssuanceCapCircuit<'_> {
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
        DriverValue<D, [RaguFp; 4]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let u16_max = RaguFp::from(u16::MAX as u64);
        let col = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.col_id_fp))?;
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let idx_m1 =
            Element::alloc(dr, alloc, witness.as_ref().map(|w| RaguFp::from(w.idx_minus_1)))?;
        let delta = Element::alloc(dr, alloc, witness.as_ref().map(|w| RaguFp::from(w.delta)))?;
        let blind = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.blinding_fp))?;

        idx_m1.enforce_le::<16>(dr, alloc, u16_max)?;
        delta.enforce_le::<16>(dr, alloc, u16_max)?;

        let idx = idx_m1.add(dr, &Element::one());
        let cap_out = idx.add(dr, &delta);

        let mut sp1 = Sponge::new(dr, self.poseidon);
        sp1.absorb(dr, &col)?;
        sp1.absorb(dr, &aid)?;
        let dom = sp1.squeeze(dr)?;

        let mut sp2 = Sponge::new(dr, self.poseidon);
        sp2.absorb(dr, &idx)?;
        sp2.absorb(dr, &blind)?;
        let blinded_idx = sp2.squeeze(dr)?;

        let mut sp3 = Sponge::new(dr, self.poseidon);
        sp3.absorb(dr, &dom)?;
        sp3.absorb(dr, &blinded_idx)?;
        let slot_cmt = sp3.squeeze(dr)?;

        let out = FixedVec::new(vec![col, aid, slot_cmt, cap_out])?;
        let data = fixed_header_value::<D, 4>(&out);
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

/// Ragu selective trait Merkle circuit (`Index 8`): proves `trait_fp` is in the asset's committed
/// `traits_root_fp` via a depth-4 Poseidon Merkle path AND proves knowledge of `secret_fp` for `owner_tag_fp`.
#[derive(Clone, Copy)]
struct AttributeWitness {
    asset_fp: RaguFp,
    secret_fp: RaguFp,
    trait_fp: RaguFp,
    siblings: [(RaguFp, bool); MERKLE_DEPTH],
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
        DriverValue<D, [RaguFp; 4]>,
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

        let mut cur = tr.clone();
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

        let mut sp_ch = Sponge::new(dr, self.poseidon);
        sp_ch.absorb(dr, &tr)?;
        sp_ch.absorb(dr, &ch)?;
        let bound_ch = sp_ch.squeeze(dr)?;

        let out = FixedVec::new(vec![aid, cur, owner_tag, bound_ch])?;
        let data = fixed_header_value::<D, 4>(&out);
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

/// Ragu Stage I -> Stage II ZSA burn-migration circuit (`Index 9`): proves knowledge of `secret_fp`
/// matching the registered `owner_tag_fp = Poseidon(secret_fp)` and derives deterministic
/// `burn_nf = Poseidon(Poseidon(asset_fp, phase1_cmt_fp), secret_fp)`.
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
        DriverValue<D, [RaguFp; 4]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let alloc = &mut Standard::new();
        let aid = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.asset_fp))?;
        let p1 = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.phase1_cmt_fp))?;
        let sec = Element::alloc(dr, alloc, witness.as_ref().map(|w| w.secret_fp))?;

        let mut sp_owner = Sponge::new(dr, self.poseidon);
        sp_owner.absorb(dr, &sec)?;
        let owner_tag = sp_owner.squeeze(dr)?;

        let mut sp_pair = Sponge::new(dr, self.poseidon);
        sp_pair.absorb(dr, &aid)?;
        sp_pair.absorb(dr, &p1)?;
        let pair_fp = sp_pair.squeeze(dr)?;

        let mut sp_nf = Sponge::new(dr, self.poseidon);
        sp_nf.absorb(dr, &pair_fp)?;
        sp_nf.absorb(dr, &sec)?;
        let burn_nf = sp_nf.squeeze(dr)?;

        let out = FixedVec::new(vec![aid, p1, owner_tag, burn_nf])?;
        let data = fixed_header_value::<D, 4>(&out);
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

struct CachedRagu {
    app: ZyozaRaguApp,
    /// Decoded once and cloned per fold: the neutral right child of every unary lineage step.
    unit_proof: Proof<Pasta, WalletRank>,
}

impl CachedRagu {
    fn build() -> Self {
        Self::build_with(None)
    }

    /// Builds the application. A stored bootstrap proof of the same configuration lets
    /// `finalize` skip its bootstrap fuse (see `ApplicationBuilder::with_bootstrap`).
    fn build_with(bootstrap: Option<Proof<Pasta, WalletRank>>) -> Self {
        let pasta = ragu::pcd::pasta::baked();
        let poseidon = Pasta::circuit_poseidon(pasta);
        let mut builder = ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new();
        if let Some(proof) = bootstrap {
            builder = builder.with_bootstrap(proof).expect("bootstrap proof shape");
        }
        let app = builder
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
            .register(IssuanceCapCircuit { poseidon })
            .expect("register IssuanceCapCircuit")
            .register(AttributeCircuit { poseidon })
            .expect("register AttributeCircuit")
            .register(MigrationCircuit { poseidon })
            .expect("register MigrationCircuit")
            .finalize(pasta)
            .expect("finalize Ragu Application");

        let rng = &mut UnwrapErr(SysRng);
        let (unit_pcd, ()) = app.seed(rng, UnitStep, ()).expect("seed UnitStep");
        let unit_proof = unit_pcd.proof().clone();
        Self { app, unit_proof }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn with_ragu<T: Send>(f: impl FnOnce(&CachedRagu) -> T + Send) -> T {
    use std::sync::{mpsc, OnceLock};

    type Job = Box<dyn FnOnce(&CachedRagu) + Send>;
    static PROVER_TX: OnceLock<mpsc::Sender<Job>> = OnceLock::new();

    let tx = PROVER_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("zyoza-ragu-prover".into())
            .spawn(move || {
                let ctx = CachedRagu::build();
                while let Ok(job) = rx.recv() {
                    job(&ctx);
                }
            })
            .expect("spawn zyoza-ragu-prover thread");
        tx
    });

    // Scope safely transmits a stack closure to the dedicated prover worker and blocks until it completes.
    let (res_tx, res_rx) = mpsc::sync_channel::<T>(1);
    let boxed: Box<dyn FnOnce(&CachedRagu) + Send> = Box::new(move |ctx| {
        let _ = res_tx.send(f(ctx));
    });
    // Extend lifetime safely because `res_rx.recv()` strictly joins completion before returning!
    let static_job: Job = unsafe { std::mem::transmute(boxed) };
    tx.send(static_job).expect("prover thread alive");
    res_rx.recv().expect("prover job completed")
}

#[cfg(target_arch = "wasm32")]
fn with_ragu<T>(f: impl FnOnce(&CachedRagu) -> T) -> T {
    thread_local! {
        static WASM_RAGU: CachedRagu = CachedRagu::build();
    }
    WASM_RAGU.with(f)
}

/// Warms up the single dedicated Ragu prover thread in the background on server startup.
pub fn warmup_prover() {
    with_ragu(|_| {});
}

/// Returns the canonical byte size of a compressed Ragu proof at `WalletRank` (`6,208 bytes`).
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

/// Derives the 32-byte `owner_tag = Poseidon(secret)` for an owner secret.
pub fn derive_owner_tag(secret_witness: &[u8]) -> [u8; 32] {
    let sec_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[secret_witness]);
    poseidon_1(sec_fp).to_bytes()
}

fn event_id_to_fp(event_id: &[u8; 32]) -> RaguFp {
    bytes_to_ragu_fp(b"ZYOZA-EVT-FP1___", &[event_id])
}

/// The nullifier a `TicketCheckInStep` exposes for `asset_id` at `event_id`:
/// `Poseidon(asset, event)`. A gate recomputes this for its own event, compares it with the
/// proof's `event_nullifier_bytes`, and refuses a nullifier it has already recorded.
pub fn derive_ticket_event_nullifier(asset_id: &AssetId, event_id: &[u8; 32]) -> [u8; 32] {
    let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
    poseidon_2(asset_fp, event_id_to_fp(event_id)).to_bytes()
}

/// Derives the 32-byte `creator_tag = Poseidon(creator_royalty_secret)` for royalty receipts.
pub fn derive_creator_tag(creator_secret: &[u8]) -> [u8; 32] {
    let sec_fp = bytes_to_ragu_fp(b"ZYOZA-ROY-FP1___", &[creator_secret]);
    poseidon_1(sec_fp).to_bytes()
}

fn merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut layer: Vec<RaguFp> = leaves
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

fn merkle_path_from_leaves(leaves: &[[u8; 32]], mut index: usize) -> Vec<([u8; 32], bool)> {
    let mut layer: Vec<RaguFp> = leaves
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

/// Fixed-depth (`MERKLE_DEPTH = 4`, up to 16 assets) Poseidon Merkle collection registry
/// binding `(asset_id, state_root, owner_tag)` for `OwnershipMerkleCircuit` proofs.
#[derive(Debug, Clone)]
pub struct CollectionMerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl CollectionMerkleTree {
    /// Builds a collection tree from `(asset_id, state_root, owner_secret)` entries.
    pub fn from_holdings(entries: &[(AssetId, [u8; 32], &[u8])]) -> Self {
        let mapped: Vec<(AssetId, [u8; 32], [u8; 32])> = entries
            .iter()
            .map(|(aid, st, sec)| (*aid, *st, derive_owner_tag(sec)))
            .collect();
        Self::from_public_tags(&mapped)
    }

    /// Builds a collection tree from public `(asset_id, state_root, owner_tag)` ledger records
    /// (so an indexer/gallery never needs any holder's private secret!).
    pub fn from_public_tags(entries: &[(AssetId, [u8; 32], [u8; 32])]) -> Self {
        let mut leaves = Vec::with_capacity(1 << MERKLE_DEPTH);
        for (aid, st_root, owner_tag) in entries {
            let aid_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&aid.0]);
            let st_fp = bytes_to_ragu_fp(b"ZYOZA-STR-FP1___", &[st_root]);
            let tag_fp = RaguFp::from_bytes(*owner_tag).expect("canonical owner_tag Fp");
            let obj_bind = poseidon_2(aid_fp, st_fp);
            let leaf = poseidon_2(obj_bind, tag_fp);
            leaves.push(leaf.to_bytes());
        }
        while leaves.len() < (1 << MERKLE_DEPTH) {
            leaves.push(RaguFp::from(0u64).to_bytes());
        }
        leaves.truncate(1 << MERKLE_DEPTH);
        Self { leaves }
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_root_from_leaves(&self.leaves)
    }

    pub fn path(&self, index: usize) -> Vec<([u8; 32], bool)> {
        merkle_path_from_leaves(&self.leaves, index)
    }
}

/// Fixed-depth (`MERKLE_DEPTH = 4`) Poseidon Merkle tree committing an object's `(key, val)` traits
/// so `AttributeCircuit` proves membership against a committed `traits_root` rather than free prover input.
#[derive(Debug, Clone)]
pub struct TraitMerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl TraitMerkleTree {
    pub fn from_traits<'a>(traits: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut leaves = Vec::with_capacity(1 << MERKLE_DEPTH);
        for (k, v) in traits {
            let tr_fp = bytes_to_ragu_fp(b"ZYOZA-TRAIT-FP1_", &[k.as_bytes(), b":", v.as_bytes()]);
            leaves.push(tr_fp.to_bytes());
        }
        while leaves.len() < (1 << MERKLE_DEPTH) {
            leaves.push(RaguFp::from(0u64).to_bytes());
        }
        leaves.truncate(1 << MERKLE_DEPTH);
        Self { leaves }
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_root_from_leaves(&self.leaves)
    }

    pub fn path(&self, index: usize) -> Vec<([u8; 32], bool)> {
        merkle_path_from_leaves(&self.leaves, index)
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
    pub fn code(self) -> u64 {
        match self {
            Self::MintStep => 1,
            Self::TransferStep => 2,
            Self::RoyaltyStep => 3,
            Self::TicketCheckInStep => 4,
            Self::AttributeUpgradeStep => 5,
        }
    }

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
    /// Current holder's secret preimage (checked against `prior.owner_tag_bytes` on every fold).
    pub secret_witness: Vec<u8>,
    /// Next holder's `owner_tag` (`None` keeps the current owner).
    pub next_owner_tag: Option<[u8; 32]>,
    /// Sticky royalty flag set at `MintStep`.
    pub royalty_required: bool,
    /// Sticky creator receipt tag set at `MintStep` (`derive_creator_tag`).
    pub creator_tag: [u8; 32],
    /// Creator/escrow receipt secret preimage supplied on `RoyaltyStep`.
    pub creator_ack_secret: Option<Vec<u8>>,
    /// The event being checked in to. Required on `TicketCheckInStep`: the step exposes
    /// `derive_ticket_event_nullifier(asset_id, event_id)` so a gate can refuse a second check-in.
    #[serde(default)]
    pub event_id: Option<[u8; 32]>,
}

/// Recursive Ragu PCD proof bundle. Every public field on this struct is reconstructed into
/// `LineageHeader` (`10` field elements) inside `verify_pcd`, so tampering with `step_count`,
/// `last_step`, `last_profile`, `owner_tag_bytes`, `royalty_required`, or `event_nullifier_bytes`
/// causes `Application::verify_compressed` to reject the proof!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaguPcdProof {
    pub asset_id: AssetId,
    pub genesis_commitment: [u8; 32],
    pub latest_commitment: [u8; 32],
    pub owner_tag_bytes: [u8; 32],
    pub step_count: u64,
    pub last_step: RaguStepKind,
    pub last_profile: ProfileId,
    pub royalty_required: bool,
    pub creator_tag_bytes: [u8; 32],
    pub event_nullifier_bytes: [u8; 32],
    pub uncompressed_proof: Vec<u8>,
    pub compressed_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaguCapProof {
    pub slot_commitment_bytes: [u8; 32],
    pub compressed_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaguMigrationProof {
    pub burn_nullifier_bytes: [u8; 32],
    pub compressed_proof: Vec<u8>,
}

/// Ragu 16-bit supply-cap prover/verifier bound to `(collection_id, asset_id, slot_commitment, max_supply)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct IssuanceCapEngine;

impl IssuanceCapEngine {
    /// Proves `1 <= token_index <= max_supply <= 65,535` bound to `(collection_id, asset_id)`.
    pub fn prove_cap(
        &self,
        collection_id: [u8; 32],
        asset_id: &AssetId,
        token_index: u64,
        blinding: [u8; 32],
        max_supply: u64,
    ) -> Result<RaguCapProof, ZyozaError> {
        let (idx_minus_1, delta) = if token_index == 0 {
            (0, max_supply.min(u16::MAX as u64))
        } else {
            (
                (token_index - 1).min(u16::MAX as u64),
                max_supply.saturating_sub(token_index).min(u16::MAX as u64),
            )
        };
        let col_id_fp = bytes_to_ragu_fp(b"ZYOZA-COL-FP1___", &[&collection_id]);
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
        let blinding_fp = bytes_to_ragu_fp(b"ZYOZA-BLD-FP1___", &[&blinding]);

        with_ragu(move |ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);
            let (pcd, ()) = ctx
                .app
                .seed(
                    rng,
                    IssuanceCapCircuit { poseidon },
                    IssuanceCapWitness {
                        col_id_fp,
                        asset_fp,
                        idx_minus_1,
                        delta,
                        blinding_fp,
                    },
                )
                .map_err(|e| ZyozaError::Proof(format!("ragu cap seed: {e:?}")))?;
            let slot_cmt = pcd.data()[2].to_bytes();
            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu cap compress: {e:?}")))?;
            let compressed_proof = compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode cap proof: {e:?}")))?;
            Ok(RaguCapProof {
                slot_commitment_bytes: slot_cmt,
                compressed_proof,
            })
        })
    }

    /// Verifies a Ragu supply-cap proof against `(collection_id, asset_id, max_supply)`.
    pub fn verify_cap(
        &self,
        collection_id: [u8; 32],
        asset_id: &AssetId,
        max_supply: u64,
        proof: &RaguCapProof,
    ) -> Result<bool, ZyozaError> {
        if proof.compressed_proof.len() != compressed_proof_len() || max_supply > u16::MAX as u64 {
            return Ok(false);
        }
        let Some(slot_cmt_fp) = RaguFp::from_bytes(proof.slot_commitment_bytes) else {
            return Ok(false);
        };
        let col_id_fp = bytes_to_ragu_fp(b"ZYOZA-COL-FP1___", &[&collection_id]);
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
        let proof_bytes = proof.compressed_proof.clone();

        with_ragu(move |ctx| {
            let decoded = CompressedProof::<Pasta>::from_bytes(&proof_bytes)
                .map_err(|e| ZyozaError::Proof(format!("decode cap proof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<CapHeader>([
                    col_id_fp,
                    asset_fp,
                    slot_cmt_fp,
                    RaguFp::from(max_supply),
                ]))
                .map_err(|e| ZyozaError::Proof(format!("verify cap proof: {e:?}")))
        })
    }
}

/// Unified Ragu Non-Uniform Recursive PCD & ZK engine over Pasta (`WalletRank = R<13>`).
#[derive(Debug, Default, Clone, Copy)]
pub struct RaguPcdEngine;

impl RaguPcdEngine {
    /// Seeds (`prev == None`) or recursively fuses (`prev == Some(...)`) a non-uniform Ragu step,
    /// and compresses the result so it can be verified straight away.
    pub fn fold_step(
        &self,
        prev: Option<&RaguPcdProof>,
        step: &RaguStepWitness,
    ) -> Result<RaguPcdProof, ZyozaError> {
        self.fold_inner(prev, step, true)
    }

    /// Like [`fold_step`](Self::fold_step) but skips compression, which is roughly 40% of a
    /// fold. The returned proof has an empty `compressed_proof`; it can still be folded
    /// further, and [`compress_pcd`](Self::compress_pcd) or [`verify_pcd`](Self::verify_pcd)
    /// compress it when a verifier needs it. Use this for hops nobody verifies.
    pub fn fold_step_deferred(
        &self,
        prev: Option<&RaguPcdProof>,
        step: &RaguStepWitness,
    ) -> Result<RaguPcdProof, ZyozaError> {
        self.fold_inner(prev, step, false)
    }

    /// Fills in `compressed_proof` for a proof made by `fold_step_deferred`. No-op otherwise.
    pub fn compress_pcd(&self, proof: &mut RaguPcdProof) -> Result<(), ZyozaError> {
        if !proof.compressed_proof.is_empty() {
            return Ok(());
        }
        let data = lineage_data_from_proof(proof)?;
        let bytes = std::mem::take(&mut proof.uncompressed_proof);
        let (bytes, compressed) = with_ragu(move |ctx| {
            let out = compress_lineage(ctx, &bytes, data);
            (bytes, out)
        });
        proof.uncompressed_proof = bytes;
        proof.compressed_proof = compressed?;
        Ok(())
    }

    fn fold_inner(
        &self,
        prev: Option<&RaguPcdProof>,
        step: &RaguStepWitness,
        compress: bool,
    ) -> Result<RaguPcdProof, ZyozaError> {
        let prev_cloned = prev.cloned();
        let step_cloned = step.clone();

        with_ragu(move |ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

            let profile_fp = bytes_to_ragu_fp(b"ZYOZA-PROF-FP1__", &[&step_cloned.profile_id]);
            let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&step_cloned.asset_id.0]);
            let commit_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&step_cloned.state_commitment]);
            let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[&step_cloned.secret_witness]);
            let cur_owner_tag_fp = poseidon_1(secret_fp);

            let (pcd, genesis_commitment, next_count, royalty_req, creator_tag_bytes) =
                match (prev_cloned.as_ref(), step_cloned.kind) {
                    (None, RaguStepKind::MintStep) => {
                        let creator_tag_fp =
                            RaguFp::from_bytes(step_cloned.creator_tag).ok_or_else(|| {
                                ZyozaError::Proof("non-canonical creator_tag Fp".into())
                            })?;
                        let (seeded, ()) = ctx
                            .app
                            .seed(
                                rng,
                                MintCircuit { poseidon },
                                MintWitness {
                                    profile_fp,
                                    asset_fp,
                                    commit_fp,
                                    owner_secret_fp: secret_fp,
                                    royalty_required: step_cloned.royalty_required,
                                    creator_tag_fp,
                                },
                            )
                            .map_err(|e| {
                                ZyozaError::Proof(format!("ragu seed MintCircuit: {e:?}"))
                            })?;
                        (
                            seeded,
                            step_cloned.state_commitment,
                            1,
                            step_cloned.royalty_required,
                            step_cloned.creator_tag,
                        )
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
                        if prior.asset_id != step_cloned.asset_id {
                            return Err(ZyozaError::Proof("PCD fold asset_id mismatch".into()));
                        }
                        if cur_owner_tag_fp.to_bytes() != prior.owner_tag_bytes {
                            return Err(ZyozaError::Proof(
                                "secret_witness does not match current PCD owner_tag".into(),
                            ));
                        }
                        if kind == RaguStepKind::TransferStep && prior.royalty_required {
                            return Err(ZyozaError::Proof(
                                "TransferStep rejected: genesis policy requires RoyaltyStep".into(),
                            ));
                        }

                        let prior_data = lineage_data_from_proof(prior)?;
                        let left_pcd = Proof::<Pasta, WalletRank>::from_bytes(
                            &prior.uncompressed_proof,
                        )
                        .map_err(|e| ZyozaError::Proof(format!("decode left Proof: {e:?}")))?
                        .carry::<LineageHeader>(prior_data);
                        let unit_pcd = ctx.unit_proof.clone().carry::<()>(());

                        let next_owner_tag_fp = match step_cloned.next_owner_tag {
                            Some(t) => RaguFp::from_bytes(t).ok_or_else(|| {
                                ZyozaError::Proof("non-canonical next_owner_tag Fp".into())
                            })?,
                            None => cur_owner_tag_fp,
                        };
                        let common = FoldCommonWitness {
                            asset_fp,
                            prev_commit_fp: prior_data[SLOT_LATEST],
                            next_commit_fp: commit_fp,
                            profile_fp,
                            current_owner_secret_fp: secret_fp,
                            next_owner_tag_fp,
                        };
                        let (fused, ()) = match kind {
                            RaguStepKind::TransferStep => ctx.app.fuse(
                                rng,
                                TransferCircuit { poseidon },
                                common,
                                left_pcd,
                                unit_pcd,
                            ),
                            RaguStepKind::RoyaltyStep => {
                                let ack_bytes = step_cloned
                                    .creator_ack_secret
                                    .as_deref()
                                    .unwrap_or(b"");
                                let ack_fp = bytes_to_ragu_fp(b"ZYOZA-ROY-FP1___", &[ack_bytes]);
                                if prior.royalty_required
                                    && poseidon_1(ack_fp).to_bytes() != prior.creator_tag_bytes
                                {
                                    return Err(ZyozaError::Proof(
                                        "RoyaltyCircuit rejected: invalid or missing creator royalty receipt".into(),
                                    ));
                                }
                                ctx.app.fuse(
                                    rng,
                                    RoyaltyCircuit { poseidon },
                                    RoyaltyWitness {
                                        common,
                                        creator_ack_secret_fp: ack_fp,
                                    },
                                    left_pcd,
                                    unit_pcd,
                                )
                            }
                            RaguStepKind::TicketCheckInStep => {
                                let event_id = step_cloned.event_id.ok_or_else(|| {
                                    ZyozaError::Proof(
                                        "TicketCheckInStep requires an event_id".into(),
                                    )
                                })?;
                                ctx.app.fuse(
                                    rng,
                                    TicketCheckInCircuit { poseidon },
                                    TicketWitness { common, event_id_fp: event_id_to_fp(&event_id) },
                                    left_pcd,
                                    unit_pcd,
                                )
                            }
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

                        (
                            fused,
                            prior.genesis_commitment,
                            prior.step_count + 1,
                            prior.royalty_required,
                            prior.creator_tag_bytes,
                        )
                    }
                };

            let header_data = *pcd.data();
            let uncompressed_proof = pcd
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode uncompressed proof: {e:?}")))?;
            let compressed_proof = if compress {
                ctx.app
                    .compress(&pcd, rng)
                    .map_err(|e| ZyozaError::Proof(format!("ragu compress: {e:?}")))?
                    .proof()
                    .to_bytes()
                    .map_err(|e| ZyozaError::Proof(format!("encode compressed proof: {e:?}")))?
            } else {
                Vec::new()
            };

            Ok(RaguPcdProof {
                asset_id: step_cloned.asset_id,
                genesis_commitment,
                latest_commitment: step_cloned.state_commitment,
                owner_tag_bytes: header_data[SLOT_OWNER_TAG].to_bytes(),
                step_count: next_count,
                last_step: step_cloned.kind,
                last_profile: step_cloned.profile_id,
                royalty_required: royalty_req,
                creator_tag_bytes,
                event_nullifier_bytes: header_data[SLOT_EVENT_NF].to_bytes(),
                uncompressed_proof,
                compressed_proof,
            })
        })
    }

    /// Cryptographically verifies all 10 header slots of a `RaguPcdProof` via `verify_compressed`.
    ///
    /// A proof from `fold_step_deferred` (empty `compressed_proof`) is compressed here first.
    pub fn verify_pcd(&self, proof: &RaguPcdProof) -> Result<bool, ZyozaError> {
        let Ok(data) = lineage_data_from_proof(proof) else {
            return Ok(false);
        };
        let deferred = proof.compressed_proof.is_empty() && !proof.uncompressed_proof.is_empty();
        if !deferred && proof.compressed_proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        let compressed = proof.compressed_proof.clone();
        let uncompressed = if deferred { proof.uncompressed_proof.clone() } else { Vec::new() };
        with_ragu(move |ctx| {
            let proof_bytes = if deferred {
                compress_lineage(ctx, &uncompressed, data)?
            } else {
                compressed
            };
            let decoded = CompressedProof::<Pasta>::from_bytes(&proof_bytes)
                .map_err(|e| ZyozaError::Proof(format!("decode CompressedProof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<LineageHeader>(data))
                .map_err(|e| ZyozaError::Proof(format!("ragu verify_compressed: {e:?}")))
        })
    }

    /// Generates a Ragu Poseidon-Merkle ZK ownership proof bound to `(collection_root, state_root, challenge)`.
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
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&req.asset_id.0]);
        let state_root_fp = bytes_to_ragu_fp(b"ZYOZA-STR-FP1___", &[&req.state_root]);
        let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[&req.secret_witness]);
        let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&req.challenge]);

        let mut siblings = [(RaguFp::from(0u64), true); MERKLE_DEPTH];
        for (i, (sib_bytes, is_right)) in req.merkle_siblings.iter().enumerate() {
            let sib_fp = RaguFp::from_bytes(*sib_bytes)
                .ok_or_else(|| ZyozaError::Proof("non-canonical Merkle sibling Fp".into()))?;
            siblings[i] = (sib_fp, *is_right);
        }

        with_ragu(move |ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

            let (pcd, ()) = ctx
                .app
                .seed(
                    rng,
                    OwnershipMerkleCircuit { poseidon },
                    OwnershipMerkleWitness {
                        asset_fp,
                        state_root_fp,
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

    /// Verifies a Ragu Poseidon-Merkle ZK ownership proof against `(collection_root, state_root, challenge)`.
    pub fn verify_merkle_ownership(
        &self,
        req: &OwnershipVerifyRequest,
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        if proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        let Some(root_fp) = RaguFp::from_bytes(req.collection_root) else {
            return Ok(false);
        };
        let state_root_fp = bytes_to_ragu_fp(b"ZYOZA-STR-FP1___", &[&req.state_root]);
        let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&req.challenge]);
        let proof_bytes = proof.to_vec();

        with_ragu(move |ctx| {
            let decoded = CompressedProof::<Pasta>::from_bytes(&proof_bytes)
                .map_err(|e| ZyozaError::Proof(format!("decode ownership CompressedProof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<OwnershipHeader>([
                    root_fp,
                    state_root_fp,
                    challenge_fp,
                ]))
                .map_err(|e| ZyozaError::Proof(format!("verify ownership: {e:?}")))
        })
    }

    /// Proves that `(trait_key, trait_val)` is committed inside `traits_root` via `merkle_siblings`
    /// and that the prover holds the secret for `owner_tag`.
    pub fn prove_attribute(
        &self,
        asset_id: &AssetId,
        trait_key: &str,
        trait_val: &str,
        merkle_siblings: &[([u8; 32], bool)],
        secret_witness: &[u8],
        challenge: [u8; 32],
    ) -> Result<ProofBytes, ZyozaError> {
        if merkle_siblings.len() != MERKLE_DEPTH {
            return Err(ZyozaError::Proof("expected 4 trait merkle_siblings".into()));
        }
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
        let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[secret_witness]);
        let trait_fp = bytes_to_ragu_fp(
            b"ZYOZA-TRAIT-FP1_",
            &[trait_key.as_bytes(), b":", trait_val.as_bytes()],
        );
        let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&challenge]);

        let mut siblings = [(RaguFp::from(0u64), true); MERKLE_DEPTH];
        for (i, (sib_bytes, is_right)) in merkle_siblings.iter().enumerate() {
            let sib_fp = RaguFp::from_bytes(*sib_bytes)
                .ok_or_else(|| ZyozaError::Proof("non-canonical trait sibling Fp".into()))?;
            siblings[i] = (sib_fp, *is_right);
        }

        with_ragu(move |ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

            let (pcd, ()) = ctx
                .app
                .seed(
                    rng,
                    AttributeCircuit { poseidon },
                    AttributeWitness {
                        asset_fp,
                        secret_fp,
                        trait_fp,
                        siblings,
                        challenge_fp,
                    },
                )
                .map_err(|e| ZyozaError::Proof(format!("ragu attribute seed: {e:?}")))?;
            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu attribute compress: {e:?}")))?;
            compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode attribute proof: {e:?}")))
        })
    }

    /// Verifies a Ragu `AttributeCircuit` proof against public `(asset_id, traits_root, owner_tag, trait_key, trait_val, challenge)`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_attribute(
        &self,
        asset_id: &AssetId,
        traits_root: [u8; 32],
        owner_tag: [u8; 32],
        trait_key: &str,
        trait_val: &str,
        challenge: [u8; 32],
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        if proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        let Some(traits_root_fp) = RaguFp::from_bytes(traits_root) else {
            return Ok(false);
        };
        let Some(owner_tag_fp) = RaguFp::from_bytes(owner_tag) else {
            return Ok(false);
        };
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
        let trait_fp = bytes_to_ragu_fp(
            b"ZYOZA-TRAIT-FP1_",
            &[trait_key.as_bytes(), b":", trait_val.as_bytes()],
        );
        let challenge_fp = bytes_to_ragu_fp(b"ZYOZA-CHAL-FP1__", &[&challenge]);
        let bound_ch = poseidon_2(trait_fp, challenge_fp);
        let proof_bytes = proof.to_vec();

        with_ragu(move |ctx| {
            let decoded = CompressedProof::<Pasta>::from_bytes(&proof_bytes)
                .map_err(|e| ZyozaError::Proof(format!("decode attribute proof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<AttributeHeader>([
                    asset_fp,
                    traits_root_fp,
                    owner_tag_fp,
                    bound_ch,
                ]))
                .map_err(|e| ZyozaError::Proof(format!("verify attribute proof: {e:?}")))
        })
    }

    /// Generates a Ragu `MigrationCircuit` proof bound to `(asset_id, phase1_commitment, owner_tag)`.
    pub fn prove_migration(
        &self,
        asset_id: &AssetId,
        phase1_commitment: [u8; 32],
        secret_witness: &[u8],
    ) -> Result<ProofBytes, ZyozaError> {
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
        let phase1_cmt_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&phase1_commitment]);
        let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[secret_witness]);

        with_ragu(move |ctx| {
            let pasta = ragu::pcd::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(pasta);
            let rng = &mut UnwrapErr(SysRng);

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
            let burn_nf = pcd.data()[3].to_bytes();
            let compressed = ctx
                .app
                .compress(&pcd, rng)
                .map_err(|e| ZyozaError::Proof(format!("ragu migration compress: {e:?}")))?;
            let compressed_proof = compressed
                .proof()
                .to_bytes()
                .map_err(|e| ZyozaError::Proof(format!("encode migration proof: {e:?}")))?;

            serde_json::to_vec(&RaguMigrationProof {
                burn_nullifier_bytes: burn_nf,
                compressed_proof,
            })
            .map_err(|e| ZyozaError::Proof(format!("serialize migration proof: {e}")))
        })
    }

    /// Verifies a Ragu `MigrationCircuit` proof against public `(asset_id, phase1_commitment, expected_owner_tag)`.
    /// Any attacker without the secret preimage of `expected_owner_tag` is rejected!
    pub fn verify_migration(
        &self,
        asset_id: &AssetId,
        phase1_commitment: [u8; 32],
        expected_owner_tag: [u8; 32],
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        let parsed: RaguMigrationProof = serde_json::from_slice(proof)
            .map_err(|e| ZyozaError::Proof(format!("parse migration proof: {e}")))?;
        if parsed.compressed_proof.len() != compressed_proof_len() {
            return Ok(false);
        }
        let Some(owner_tag_fp) = RaguFp::from_bytes(expected_owner_tag) else {
            return Ok(false);
        };
        let Some(burn_nf_fp) = RaguFp::from_bytes(parsed.burn_nullifier_bytes) else {
            return Ok(false);
        };
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
        let phase1_cmt_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&phase1_commitment]);
        let proof_bytes = parsed.compressed_proof;

        with_ragu(move |ctx| {
            let decoded = CompressedProof::<Pasta>::from_bytes(&proof_bytes)
                .map_err(|e| ZyozaError::Proof(format!("decode migration proof: {e:?}")))?;
            ctx.app
                .verify_compressed(&decoded.carry::<MigrationHeader>([
                    asset_fp,
                    phase1_cmt_fp,
                    owner_tag_fp,
                    burn_nf_fp,
                ]))
                .map_err(|e| ZyozaError::Proof(format!("verify migration proof: {e:?}")))
        })
    }
}

/// Compresses an uncompressed lineage proof carrying `data` on the prover thread.
fn compress_lineage(
    ctx: &CachedRagu,
    uncompressed: &[u8],
    data: [RaguFp; LINEAGE_SLOTS],
) -> Result<Vec<u8>, ZyozaError> {
    let rng = &mut UnwrapErr(SysRng);
    let pcd = Proof::<Pasta, WalletRank>::from_bytes(uncompressed)
        .map_err(|e| ZyozaError::Proof(format!("decode uncompressed Proof: {e:?}")))?
        .carry::<LineageHeader>(data);
    ctx.app
        .compress(&pcd, rng)
        .map_err(|e| ZyozaError::Proof(format!("ragu compress: {e:?}")))?
        .proof()
        .to_bytes()
        .map_err(|e| ZyozaError::Proof(format!("encode compressed proof: {e:?}")))
}

fn lineage_data_from_proof(proof: &RaguPcdProof) -> Result<[RaguFp; LINEAGE_SLOTS], ZyozaError> {
    let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&proof.asset_id.0]);
    let gen_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&proof.genesis_commitment]);
    let lat_fp = bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&proof.latest_commitment]);
    let owner_tag_fp = RaguFp::from_bytes(proof.owner_tag_bytes)
        .ok_or_else(|| ZyozaError::Proof("non-canonical owner_tag Fp".into()))?;
    let count_fp = RaguFp::from(proof.step_count);
    let kind_fp = RaguFp::from(proof.last_step.code());
    let prof_fp = bytes_to_ragu_fp(b"ZYOZA-PROF-FP1__", &[&proof.last_profile]);
    let roy_fp = RaguFp::from(u64::from(proof.royalty_required));
    let creator_tag_fp = RaguFp::from_bytes(proof.creator_tag_bytes)
        .ok_or_else(|| ZyozaError::Proof("non-canonical creator_tag Fp".into()))?;
    let event_nf_fp = RaguFp::from_bytes(proof.event_nullifier_bytes)
        .ok_or_else(|| ZyozaError::Proof("non-canonical event_nf Fp".into()))?;

    Ok([
        asset_fp,
        gen_fp,
        lat_fp,
        owner_tag_fp,
        count_fp,
        kind_fp,
        prof_fp,
        roy_fp,
        creator_tag_fp,
        event_nf_fp,
    ])
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
    fn real_ragu_sticky_royalty_owner_auth_and_header_completeness() {
        let engine = RaguPcdEngine;
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:ragu:real:1");
        let creator_tag = derive_creator_tag(b"creator-royalty-receipt-key");
        let bob_tag = derive_owner_tag(b"bob-sk");

        let t_init = std::time::Instant::now();
        warmup_prover();
        let init_ms = t_init.elapsed().as_millis();

        // 1. Seed MintStep (owned by alice, royalty_required = true)
        let t_seed = std::time::Instant::now();
        let pcd1 = engine
            .fold_step(
                None,
                &RaguStepWitness {
                    kind: RaguStepKind::MintStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x01; 32],
                    secret_witness: b"alice-sk".to_vec(),
                    next_owner_tag: None,
                    royalty_required: true,
                    creator_tag,
                    creator_ack_secret: None,
                    event_id: None,
                },
            )
            .unwrap();
        let seed_ms = t_seed.elapsed().as_millis();
        assert!(engine.verify_pcd(&pcd1).unwrap());

        // 2a. Skipping RoyaltyStep via TransferStep MUST be rejected!
        assert!(engine
            .fold_step(
                Some(&pcd1),
                &RaguStepWitness {
                    kind: RaguStepKind::TransferStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x02; 32],
                    secret_witness: b"alice-sk".to_vec(),
                    next_owner_tag: Some(bob_tag),
                    royalty_required: true,
                    creator_tag,
                    creator_ack_secret: None,
                    event_id: None,
                },
            )
            .is_err());

        // 2b. Wrong owner secret MUST be rejected!
        assert!(engine
            .fold_step(
                Some(&pcd1),
                &RaguStepWitness {
                    kind: RaguStepKind::RoyaltyStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x02; 32],
                    secret_witness: b"attacker-sk".to_vec(),
                    next_owner_tag: Some(bob_tag),
                    royalty_required: true,
                    creator_tag,
                    creator_ack_secret: Some(b"creator-royalty-receipt-key".to_vec()),
                    event_id: None,
                },
            )
            .is_err());

        // 2c. Missing/forged creator royalty receipt MUST be rejected both natively and in-circuit!
        assert!(engine
            .fold_step(
                Some(&pcd1),
                &RaguStepWitness {
                    kind: RaguStepKind::RoyaltyStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x02; 32],
                    secret_witness: b"alice-sk".to_vec(),
                    next_owner_tag: Some(bob_tag),
                    royalty_required: true,
                    creator_tag,
                    creator_ack_secret: Some(b"forged-receipt".to_vec()),
                    event_id: None,
                },
            )
            .is_err());

        // 3. Valid RoyaltyStep transferring ownership from alice -> bob
        let t_fold = std::time::Instant::now();
        let pcd2 = engine
            .fold_step(
                Some(&pcd1),
                &RaguStepWitness {
                    kind: RaguStepKind::RoyaltyStep,
                    profile_id: *b"NFT1",
                    asset_id,
                    state_commitment: [0x02; 32],
                    secret_witness: b"alice-sk".to_vec(),
                    next_owner_tag: Some(bob_tag),
                    royalty_required: true,
                    creator_tag,
                    creator_ack_secret: Some(b"creator-royalty-receipt-key".to_vec()),
                    event_id: None,
                },
            )
            .unwrap();
        let fold_ms = t_fold.elapsed().as_millis();

        // 4. Bob checks in a ticket (exposes non-zero event_nullifier_bytes in verified header!)
        let pcd3 = engine
            .fold_step(
                Some(&pcd2),
                &RaguStepWitness {
                    kind: RaguStepKind::TicketCheckInStep,
                    profile_id: *b"TKT1",
                    asset_id,
                    state_commitment: [0x03; 32],
                    secret_witness: b"bob-sk".to_vec(),
                    next_owner_tag: None,
                    royalty_required: true,
                    creator_tag,
                    creator_ack_secret: None,
                    event_id: Some([0x5E; 32]),
                },
            )
            .unwrap();
        assert_ne!(pcd3.event_nullifier_bytes, [0u8; 32]);
        // The nullifier is exactly the one a gate derives for this object at this event.
        assert_eq!(
            pcd3.event_nullifier_bytes,
            derive_ticket_event_nullifier(&asset_id, &[0x5E; 32])
        );

        // A second check-in at the same event, from a later state, exposes the SAME nullifier,
        // so a gate that records nullifiers refuses it. A different event gives a different one.
        let ticket = |commit: u8, event: Option<[u8; 32]>| RaguStepWitness {
            kind: RaguStepKind::TicketCheckInStep,
            profile_id: *b"TKT1",
            asset_id,
            state_commitment: [commit; 32],
            secret_witness: b"bob-sk".to_vec(),
            next_owner_tag: None,
            royalty_required: true,
            creator_tag,
            creator_ack_secret: None,
            event_id: event,
        };
        let again = engine.fold_step(Some(&pcd3), &ticket(0x04, Some([0x5E; 32]))).unwrap();
        assert!(engine.verify_pcd(&again).unwrap());
        assert_eq!(again.event_nullifier_bytes, pcd3.event_nullifier_bytes);
        let other = engine.fold_step(Some(&pcd3), &ticket(0x04, Some([0x5F; 32]))).unwrap();
        assert_ne!(other.event_nullifier_bytes, pcd3.event_nullifier_bytes);
        // A proof cannot claim another event's nullifier.
        let mut wrong_event = again.clone();
        wrong_event.event_nullifier_bytes = other.event_nullifier_bytes;
        assert!(!engine.verify_pcd(&wrong_event).unwrap());
        // The step refuses to run without an event.
        assert!(engine.fold_step(Some(&pcd3), &ticket(0x04, None)).is_err());

        let t_ver = std::time::Instant::now();
        assert!(engine.verify_pcd(&pcd3).unwrap());
        let ver_ms = t_ver.elapsed().as_millis();
        println!(
            "[Ragu 10-Slot Header Benchmark] proof={}B init={}ms warm_seed={}ms warm_fold={}ms verify={}ms",
            pcd3.compressed_proof.len(),
            init_ms,
            seed_ms,
            fold_ms,
            ver_ms
        );

        // Tampering with step_count, last_step, or last_profile MUST fail verify_compressed!
        let mut bad_count = pcd3.clone();
        bad_count.step_count = 99;
        assert!(!engine.verify_pcd(&bad_count).unwrap());

        let mut bad_step = pcd3.clone();
        bad_step.last_step = RaguStepKind::AttributeUpgradeStep;
        assert!(!engine.verify_pcd(&bad_step).unwrap());
    }

    #[test]
    fn ragu_bound_ownership_traits_migration_and_cap() {
        let engine = RaguPcdEngine;
        let a1 = AssetId::derive(&[0x01; 32], b"zyoza:col:1");
        let a2 = AssetId::derive(&[0x01; 32], b"zyoza:col:2");
        let st1 = [0xA1; 32];
        let st2 = [0xA2; 32];

        let tree = CollectionMerkleTree::from_holdings(&[
            (a1, st1, b"alice-real-secret"),
            (a2, st2, b"bob-real-secret"),
        ]);
        let root = tree.root();
        let challenge = [0x77; 32];

        // 1. Ownership bound to state_root
        let valid_proof = engine
            .prove_merkle_ownership(&OwnershipProofRequest {
                asset_id: a1,
                state_root: st1,
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
                    state_root: st1,
                    challenge,
                },
                &valid_proof
            )
            .unwrap());
        // Listing a different state_root with the same proof MUST fail!
        assert!(!engine
            .verify_merkle_ownership(
                &OwnershipVerifyRequest {
                    collection_root: root,
                    state_root: st2,
                    challenge,
                },
                &valid_proof
            )
            .unwrap());

        // 2. Trait Merkle proof bound to committed traits_root & owner_tag
        let alice_tag = derive_owner_tag(b"alice-real-secret");
        let trait_tree =
            TraitMerkleTree::from_traits([("shades", "venetian"), ("head", "dumpling")]);
        let traits_root = trait_tree.root();
        let attr_proof = engine
            .prove_attribute(
                &a1,
                "shades",
                "venetian",
                &trait_tree.path(0),
                b"alice-real-secret",
                challenge,
            )
            .unwrap();
        assert!(engine
            .verify_attribute(
                &a1,
                traits_root,
                alice_tag,
                "shades",
                "venetian",
                challenge,
                &attr_proof
            )
            .unwrap());
        // Uncommitted trait MUST fail!
        let bogus_attr_proof = engine
            .prove_attribute(
                &a1,
                "shades",
                "mythic-laser",
                &trait_tree.path(0),
                b"alice-real-secret",
                challenge,
            )
            .unwrap();
        assert!(!engine
            .verify_attribute(
                &a1,
                traits_root,
                alice_tag,
                "shades",
                "mythic-laser",
                challenge,
                &bogus_attr_proof
            )
            .unwrap());

        // 3. Migration proof bound to expected owner_tag (random attacker secret rejected!)
        let mig_proof = engine
            .prove_migration(&a1, [0x44; 32], b"alice-real-secret")
            .unwrap();
        assert!(engine
            .verify_migration(&a1, [0x44; 32], alice_tag, &mig_proof)
            .unwrap());

        let attacker_mig = engine
            .prove_migration(&a1, [0x44; 32], b"random-attacker-secret")
            .unwrap();
        assert!(!engine
            .verify_migration(&a1, [0x44; 32], alice_tag, &attacker_mig)
            .unwrap());

        // 4. Supply-cap proof bound to (collection_id, asset_id, max_supply)
        let cap_engine = IssuanceCapEngine;
        let col_id = [0xCC; 32];
        let cap_ok = cap_engine
            .prove_cap(col_id, &a1, 42, [0x11; 32], 100)
            .unwrap();
        assert!(cap_engine.verify_cap(col_id, &a1, 100, &cap_ok).unwrap());
        // Cannot reuse Token A's cap proof for Token B!
        assert!(!cap_engine.verify_cap(col_id, &a2, 100, &cap_ok).unwrap());
        // Out-of-bounds index rejected!
        let cap_over = cap_engine
            .prove_cap(col_id, &a1, 101, [0x11; 32], 100)
            .unwrap();
        assert!(!cap_engine.verify_cap(col_id, &a1, 100, &cap_over).unwrap());
    }

    #[test]
    fn deferred_fold_compresses_on_demand_and_matches_eager_statement() {
        let engine = RaguPcdEngine;
        let asset_id = AssetId::derive(&[0x03; 32], b"zyoza:deferred:1");
        let witness = |kind, n: u8| RaguStepWitness {
            kind,
            profile_id: *b"NFT1",
            asset_id,
            state_commitment: [n; 32],
            secret_witness: b"alice-sk".to_vec(),
            next_owner_tag: None,
            royalty_required: false,
            creator_tag: derive_creator_tag(b"creator"),
            creator_ack_secret: None,
            event_id: None,
        };
        let minted = engine
            .fold_step_deferred(None, &witness(RaguStepKind::MintStep, 1))
            .unwrap();
        assert!(minted.compressed_proof.is_empty());

        // A deferred proof folds further without ever being compressed.
        let mut hop = engine
            .fold_step_deferred(Some(&minted), &witness(RaguStepKind::TransferStep, 2))
            .unwrap();
        assert!(hop.compressed_proof.is_empty());
        assert_eq!(hop.step_count, 2);

        // verify_pcd compresses on demand; tampering is still rejected.
        assert!(engine.verify_pcd(&hop).unwrap());
        let mut tampered = hop.clone();
        tampered.step_count = 3;
        assert!(!engine.verify_pcd(&tampered).unwrap());

        // compress_pcd fills the field in place and is then a no-op.
        engine.compress_pcd(&mut hop).unwrap();
        assert_eq!(hop.compressed_proof.len(), compressed_proof_len());
        let first = hop.compressed_proof.clone();
        engine.compress_pcd(&mut hop).unwrap();
        assert_eq!(hop.compressed_proof, first);
        assert!(engine.verify_pcd(&hop).unwrap());
    }

    /// Stage-by-stage timing of the prover. Run with:
    /// `cargo test --release -p zyoza-proofs bench_ragu_stages -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_ragu_stages() {
        use std::time::Instant;
        fn ms(t: Instant) -> f64 {
            t.elapsed().as_secs_f64() * 1000.0
        }
        let t = Instant::now();
        let ctx = CachedRagu::build();
        println!("BENCH app_build_ms {:.0}", ms(t));

        let pasta = ragu::pcd::pasta::baked();
        let poseidon = Pasta::circuit_poseidon(pasta);
        let rng = &mut UnwrapErr(SysRng);
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:bench:1");
        let asset_fp = bytes_to_ragu_fp(b"ZYOZA-AID-FP1___", &[&asset_id.0]);
        let profile_fp = bytes_to_ragu_fp(b"ZYOZA-PROF-FP1__", &[b"NFT1"]);
        let secret_fp = bytes_to_ragu_fp(b"ZYOZA-SEC-FP1___", &[b"alice-sk"]);
        let cmt = |b: u8| bytes_to_ragu_fp(b"ZYOZA-CMT-FP1___", &[&[b; 32]]);

        let t = Instant::now();
        let (mut pcd, ()) = ctx
            .app
            .seed(
                rng,
                MintCircuit { poseidon },
                MintWitness {
                    profile_fp,
                    asset_fp,
                    commit_fp: cmt(1),
                    owner_secret_fp: secret_fp,
                    royalty_required: false,
                    creator_tag_fp: RaguFp::from(0u64),
                },
            )
            .unwrap();
        println!("BENCH seed_mint_ms {:.0}", ms(t));

        for round in 0..3u8 {
            let t = Instant::now();
            let bytes = pcd.proof().to_bytes().unwrap();
            let enc = ms(t);
            let t = Instant::now();
            let decoded = Proof::<Pasta, WalletRank>::from_bytes(&bytes).unwrap();
            let dec = ms(t);
            let t = Instant::now();
            let unit = ctx.unit_proof.clone();
            let dec_unit = ms(t);
            println!(
                "BENCH round{round} uncompressed_bytes {} encode_ms {enc:.0} decode_ms {dec:.0} clone_unit_ms {dec_unit:.0}",
                bytes.len()
            );

            let data = *pcd.data();
            let t = Instant::now();
            let (next, ()) = ctx
                .app
                .fuse(
                    rng,
                    TransferCircuit { poseidon },
                    FoldCommonWitness {
                        asset_fp,
                        prev_commit_fp: data[SLOT_LATEST],
                        next_commit_fp: cmt(2 + round),
                        profile_fp,
                        current_owner_secret_fp: secret_fp,
                        next_owner_tag_fp: poseidon_1(secret_fp),
                    },
                    decoded.carry::<LineageHeader>(data),
                    unit.carry::<()>(()),
                )
                .unwrap();
            println!("BENCH round{round} fuse_ms {:.0}", ms(t));

            let t = Instant::now();
            let compressed = ctx.app.compress(&next, rng).unwrap();
            println!("BENCH round{round} compress_ms {:.0}", ms(t));
            let cbytes = compressed.proof().to_bytes().unwrap();
            let t = Instant::now();
            let dec = CompressedProof::<Pasta>::from_bytes(&cbytes).unwrap();
            let dms = ms(t);
            let t = Instant::now();
            let ok = ctx
                .app
                .verify_compressed(&dec.carry::<LineageHeader>(*next.data()))
                .unwrap();
            println!(
                "BENCH round{round} compressed_bytes {} decode_ms {dms:.1} verify_compressed_ms {:.0} ok {ok}",
                cbytes.len(),
                ms(t)
            );
            pcd = next;
        }

        // Rebuild with the stored bootstrap proof to see what `with_bootstrap` saves.
        let boot_bytes = ctx.app.bootstrap_proof().to_bytes().unwrap();
        let t = Instant::now();
        let boot = Proof::<Pasta, WalletRank>::from_bytes(&boot_bytes).unwrap();
        let ctx2 = CachedRagu::build_with(Some(boot));
        println!(
            "BENCH app_build_with_bootstrap_ms {:.0} bootstrap_bytes {}",
            ms(t),
            boot_bytes.len()
        );
        drop(ctx2);

        let t = Instant::now();
        for _ in 0..10 {
            let _ = poseidon_1(secret_fp);
        }
        println!("BENCH poseidon_1_ms {:.2}", ms(t) / 10.0);
    }

    /// A 6-hop lineage through the public API: compress every hop versus only at the end.
    /// `cargo test --release -p zyoza-proofs bench_ragu_chain -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_ragu_chain() {
        use std::time::Instant;
        let engine = RaguPcdEngine;
        warmup_prover();
        let asset_id = AssetId::derive(&[0x02; 32], b"zyoza:bench:chain");
        let step = |kind, n: u8| RaguStepWitness {
            kind,
            profile_id: *b"NFT1",
            asset_id,
            state_commitment: [n; 32],
            secret_witness: b"alice-sk".to_vec(),
            next_owner_tag: None,
            royalty_required: false,
            creator_tag: derive_creator_tag(b"creator"),
            creator_ack_secret: None,
            event_id: None,
        };
        for deferred in [false, true] {
            let t = Instant::now();
            let fold = |prev: Option<&RaguPcdProof>, w: &RaguStepWitness| {
                if deferred {
                    engine.fold_step_deferred(prev, w)
                } else {
                    engine.fold_step(prev, w)
                }
            };
            let mut pcd = fold(None, &step(RaguStepKind::MintStep, 1)).unwrap();
            for n in 2..=6u8 {
                pcd = fold(Some(&pcd), &step(RaguStepKind::TransferStep, n)).unwrap();
            }
            let prove_ms = t.elapsed().as_secs_f64() * 1000.0;
            let t = Instant::now();
            assert!(engine.verify_pcd(&pcd).unwrap());
            let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(pcd.step_count, 6);
            println!(
                "BENCH chain6 deferred={deferred} prove_ms {prove_ms:.0} final_verify_ms {verify_ms:.0} total_ms {:.0}",
                prove_ms + verify_ms
            );
        }
    }
}
