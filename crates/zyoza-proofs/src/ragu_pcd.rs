//! Real `tachyon-zcash/ragu` Non-Uniform Proof-Carrying Data (PCD) engine over Pasta.
//!
//! Aligned with `./zashu`'s Ragu backend patterns (`FixedVec` multi-slot transition header,
//! in-circuit state/asset contiguity enforcement, `SysRng` blinding, and exact
//! `CompressedProof::encoded_len` checking), while registering Zyoza's non-uniform
//! multi-profile `Step<Pasta>` subcircuits inside `ragu::Application<'static, Pasta, WalletRank, 5>`:
//! - `Index(0)`: `UnitStep` (`() -> ()`, auxiliary empty right-hand child for unary folds)
//! - `Index(1)`: `MintCircuit` (`() -> LineageHeader`, base seed step committing `[asset, genesis, latest, acc]`)
//! - `Index(2)`: `TransferCircuit` (`(LineageHeader, ()) -> LineageHeader`, enforces `asset` + `prev_commit` contiguity)
//! - `Index(3)`: `RoyaltyCircuit` (`(LineageHeader, ()) -> LineageHeader`, enforces `req && !paid == 0` + contiguity)
//! - `Index(4)`: `TicketCheckInCircuit` (`(LineageHeader, ()) -> LineageHeader`, Poseidon ticket nullifier + contiguity)
//! - `Index(5)`: `UpgradeCircuit` (`(LineageHeader, ()) -> LineageHeader`, `GAM1` state upgrade + contiguity)
//! - `Index(6)`: `OwnershipMerkleCircuit` (`() -> OwnershipHeader`, 4-level Poseidon Merkle inclusion + challenge binding)

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

/// Ragu `Header` carrying `Poseidon(collection_root, challenge)` for ZK ownership proofs.
pub struct OwnershipHeader;

impl Header<RaguFp> for OwnershipHeader {
    const SUFFIX: Suffix = Suffix::new(1);
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

/// Shared contiguity & lineage transition helper for recursive steps.
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

    // Contiguity invariants (zashu pattern):
    // 1. Asset identity never changes across recursive hops.
    left_gadget[SLOT_ASSET].sub(dr, &aid).enforce_zero(dr)?;
    // 2. Prior step's latest state commitment equals this step's input commitment.
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

        // In-circuit boolean royalty compliance gate: royalty_required && !royalty_paid == 0
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

        // Derive one-time ticket check-in nullifier in-circuit
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

/// Ragu circuit proving:
/// 1. `owner_tag = Poseidon(secret)`
/// 2. `leaf = Poseidon(asset_id, owner_tag)`
/// 3. `root` = 4-level Poseidon Merkle path from `leaf` using `siblings`
/// 4. Public `OwnershipHeader = Poseidon(root, challenge)`
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

/// Returns the canonical byte size of a compressed Ragu proof at `WalletRank`.
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

/// Real Ragu Non-Uniform Recursive PCD engine over Pasta (`WalletRank = R<13>`).
#[derive(Debug, Default, Clone, Copy)]
pub struct RaguPcdEngine;

impl RaguPcdEngine {
    /// Seeds (`prev == None`) or recursively fuses (`prev == Some(...)`) a non-uniform Ragu step.
    pub fn fold_step(
        &self,
        prev: Option<&RaguPcdProof>,
        step: &RaguStepWitness,
    ) -> Result<RaguPcdProof, ZyozaError> {
        // Pre-check royalty compliance natively for clear error reporting, in addition to the in-circuit gate.
        if step.kind == RaguStepKind::RoyaltyStep && step.royalty_required && !step.royalty_paid {
            return Err(ZyozaError::Proof(
                "RoyaltyCircuit violation: required creator loyalty unpaid".into(),
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
    /// Any random secret or unindexed `AssetId` produces a different Merkle root and fails verification!
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

        // 1. Seed MintStep
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

        // 2. Unpaid required royalty is rejected!
        let bad_royalty = engine.fold_step(
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
        );
        assert!(bad_royalty.is_err());

        // Also test forging an unpaid RoyaltyCircuit directly at the Ragu circuit level to verify the in-circuit boolean gate!
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
            assert!(
                !ctx.app.verify_compressed(&compressed_forged).unwrap(),
                "in-circuit RoyaltyCircuit boolean gate MUST reject unpaid required royalty!"
            );
        });

        // 3. Paid RoyaltyStep + TicketCheckInStep (TKT1) + AttributeUpgradeStep (GAM1)
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

        assert_eq!(pcd4.step_count, 4);
        assert_eq!(pcd4.genesis_commitment, [0x01; 32]);
        assert_eq!(pcd4.latest_commitment, [0x04; 32]);
        assert_eq!(pcd4.compressed_proof.len(), len_1);
        println!(
            "Real Ragu PCD verified! compressed_proof={}B seed={}ms fold={}ms verify={}ms",
            len_1, seed_ms, fold_ms, ver_ms
        );

        // Tampering with latest_commitment or genesis_commitment or header_bytes MUST fail verify_compressed!
        let mut tampered_latest = pcd4.clone();
        tampered_latest.latest_commitment = [0x99; 32];
        assert!(!engine.verify_pcd(&tampered_latest).unwrap());

        let mut tampered_acc = pcd4.clone();
        tampered_acc.header_bytes = pcd1.header_bytes;
        assert!(!engine.verify_pcd(&tampered_acc).unwrap());

        // Unknown step string rejected strictly
        assert!(RaguStepKind::parse_strict("Bogus").is_err());
    }

    #[test]
    fn ragu_merkle_ownership_rejects_wrong_secret_or_unlisted_asset() {
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

        // Valid owner proof for a1 (index 0) passes
        let t_own = std::time::Instant::now();
        let valid_proof = engine
            .prove_merkle_ownership(&OwnershipProofRequest {
                asset_id: a1,
                collection_root: root,
                merkle_siblings: tree.path(0),
                secret_witness: b"alice-real-secret".to_vec(),
                challenge,
            })
            .unwrap();
        let own_prove_ms = t_own.elapsed().as_millis();
        let t_own_ver = std::time::Instant::now();
        assert!(engine
            .verify_merkle_ownership(
                &OwnershipVerifyRequest {
                    collection_root: root,
                    challenge,
                },
                &valid_proof
            )
            .unwrap());
        let own_ver_ms = t_own_ver.elapsed().as_millis();
        println!(
            "Ragu Merkle Ownership: proof={}B prove={}ms verify={}ms",
            valid_proof.len(),
            own_prove_ms,
            own_ver_ms
        );

        // Random / wrong secret MUST fail verification!
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

        // Unlisted asset MUST fail verification!
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
    }
}
