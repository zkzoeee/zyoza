//! FROST-style t-of-n threshold Schnorr issuer signing over Pasta (`Pallas`) for ZSA issuance.

use blake2b_simd::Params;
use ff::{Field, FromUniformBytes};
use group::{Group, GroupEncoding};
use zyoza_core::ZyozaError;
use pasta_curves::pallas;
use rand::Rng;

const PERSONAL_FROST_CHAL: &[u8; 16] = b"ZYOZA-FROST-CH1_";

/// A single participant's Shamir key share for threshold ZSA issuance.
#[derive(Clone)]
pub struct IssuerShare {
    pub index: u64,
    pub secret_share: pallas::Scalar,
    pub group_pk: pallas::Point,
}

/// Round-1 nonce commitment published by a signing participant.
#[derive(Clone)]
pub struct NonceCommit {
    pub index: u64,
    pub hiding: pallas::Scalar,
    pub commitment: pallas::Point,
}

/// Round-2 partial signature from one participant.
#[derive(Clone)]
pub struct PartialSignature {
    pub index: u64,
    pub z_i: pallas::Scalar,
}

/// Aggregated threshold Schnorr signature authorizing a ZSA issuance bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignature {
    pub r_bytes: [u8; 32],
    pub s_bytes: [u8; 32],
}

/// Performs trusted-dealer Shamir keygen for `threshold`-of-`total` participants on Pallas.
pub fn keygen_dealer<R: Rng + ?Sized>(
    rng: &mut R,
    threshold: usize,
    total: usize,
) -> Result<(pallas::Point, Vec<IssuerShare>), ZyozaError> {
    if threshold == 0 || threshold > total {
        return Err(ZyozaError::Settlement(
            "invalid threshold parameters".into(),
        ));
    }

    let mut coeffs = Vec::with_capacity(threshold);
    for _ in 0..threshold {
        coeffs.push(random_scalar(rng));
    }
    let group_pk = pallas::Point::generator() * coeffs[0];

    let mut shares = Vec::with_capacity(total);
    for idx in 1..=(total as u64) {
        let x = pallas::Scalar::from(idx);
        let mut y = pallas::Scalar::ZERO;
        let mut x_pow = pallas::Scalar::ONE;
        for c in &coeffs {
            y += *c * x_pow;
            x_pow *= x;
        }
        shares.push(IssuerShare {
            index: idx,
            secret_share: y,
            group_pk,
        });
    }

    Ok((group_pk, shares))
}

/// Round 1: generates a participant's nonce and commitment.
pub fn round1_commit<R: Rng + ?Sized>(rng: &mut R, share: &IssuerShare) -> NonceCommit {
    let hiding = random_scalar(rng);
    let commitment = pallas::Point::generator() * hiding;
    NonceCommit {
        index: share.index,
        hiding,
        commitment,
    }
}

/// Round 2: computes a participant's partial signature over `issuance_bundle`.
pub fn round2_sign(
    share: &IssuerShare,
    commit: &NonceCommit,
    all_commits: &[NonceCommit],
    issuance_bundle: &[u8],
) -> PartialSignature {
    let group_r = all_commits
        .iter()
        .fold(pallas::Point::identity(), |acc, c| acc + c.commitment);
    let challenge = frost_challenge(&group_r, &share.group_pk, issuance_bundle);
    let indices: Vec<u64> = all_commits.iter().map(|c| c.index).collect();
    let lambda_i = lagrange_coeff(share.index, &indices);
    let z_i = commit.hiding + challenge * lambda_i * share.secret_share;
    PartialSignature {
        index: share.index,
        z_i,
    }
}

/// Aggregates partial signatures into a single `FrostSignature`.
pub fn aggregate_signatures(
    all_commits: &[NonceCommit],
    partials: &[PartialSignature],
) -> Result<FrostSignature, ZyozaError> {
    if all_commits.len() != partials.len() || partials.is_empty() {
        return Err(ZyozaError::Settlement(
            "mismatched commit/partial signature count".into(),
        ));
    }
    let group_r = all_commits
        .iter()
        .fold(pallas::Point::identity(), |acc, c| acc + c.commitment);
    let s = partials
        .iter()
        .fold(pallas::Scalar::ZERO, |acc, p| acc + p.z_i);

    Ok(FrostSignature {
        r_bytes: group_r.to_bytes(),
        s_bytes: scalar_to_bytes(&s),
    })
}

/// Verifies a `FrostSignature` against the group public key and `issuance_bundle`.
pub fn verify_frost_signature(
    group_pk: &pallas::Point,
    issuance_bundle: &[u8],
    sig: &FrostSignature,
) -> Result<bool, ZyozaError> {
    let r_pt = Option::<pallas::Point>::from(pallas::Point::from_bytes(&sig.r_bytes))
        .ok_or_else(|| ZyozaError::Settlement("invalid FROST R point".into()))?;
    let s = Option::<pallas::Scalar>::from(pallas::Scalar::from_uniform_bytes(&pad_64(&sig.s_bytes)))
        .ok_or_else(|| ZyozaError::Settlement("invalid FROST s scalar".into()))?;
    // Use exact canonical scalar decoding via from_repr:
    let _ = s;
    let s_exact = bytes_to_scalar(&sig.s_bytes)?;
    let c = frost_challenge(&r_pt, group_pk, issuance_bundle);
    let lhs = pallas::Point::generator() * s_exact;
    let rhs = r_pt + (*group_pk * c);
    Ok(lhs == rhs)
}

fn frost_challenge(
    group_r: &pallas::Point,
    group_pk: &pallas::Point,
    msg: &[u8],
) -> pallas::Scalar {
    let mut h = Params::new()
        .hash_length(64)
        .personal(PERSONAL_FROST_CHAL)
        .to_state();
    h.update(&group_r.to_bytes());
    h.update(&group_pk.to_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(h.finalize().as_bytes());
    pallas::Scalar::from_uniform_bytes(&wide)
}

fn lagrange_coeff(i: u64, indices: &[u64]) -> pallas::Scalar {
    let xi = pallas::Scalar::from(i);
    let mut num = pallas::Scalar::ONE;
    let mut den = pallas::Scalar::ONE;
    for &j in indices {
        if j != i {
            let xj = pallas::Scalar::from(j);
            num *= xj;
            den *= xj - xi;
        }
    }
    num * den.invert().expect("distinct indices")
}

fn random_scalar<R: Rng + ?Sized>(rng: &mut R) -> pallas::Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    pallas::Scalar::from_uniform_bytes(&wide)
}

fn scalar_to_bytes(s: &pallas::Scalar) -> [u8; 32] {
    use ff::PrimeField;
    s.to_repr()
}

fn bytes_to_scalar(b: &[u8; 32]) -> Result<pallas::Scalar, ZyozaError> {
    use ff::PrimeField;
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*b))
        .ok_or_else(|| ZyozaError::Settlement("non-canonical FROST scalar".into()))
}

fn pad_64(b: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(b);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn frost_2_of_3_zsa_issuance_signing() {
        let mut rng = StdRng::seed_from_u64(777);
        let (group_pk, shares) = keygen_dealer(&mut rng, 2, 3).unwrap();
        let issuance_bundle = b"zsa-issuance:zyoza-genesis-0001";

        // Participants 1 and 3 sign (2-of-3)
        let c1 = round1_commit(&mut rng, &shares[0]);
        let c3 = round1_commit(&mut rng, &shares[2]);
        let commits = vec![c1.clone(), c3.clone()];

        let p1 = round2_sign(&shares[0], &c1, &commits, issuance_bundle);
        let p3 = round2_sign(&shares[2], &c3, &commits, issuance_bundle);

        let sig = aggregate_signatures(&commits, &[p1, p3]).unwrap();
        assert!(verify_frost_signature(&group_pk, issuance_bundle, &sig).unwrap());

        // Wrong bundle must fail
        assert!(!verify_frost_signature(&group_pk, b"tampered-bundle", &sig).unwrap());

        // 1-of-3 alone cannot forge valid signature
        let c_only = round1_commit(&mut rng, &shares[0]);
        let p_only = round2_sign(&shares[0], &c_only, &[c_only.clone()], issuance_bundle);
        let bad_sig = aggregate_signatures(&[c_only], &[p_only]).unwrap();
        assert!(!verify_frost_signature(&group_pk, issuance_bundle, &bad_sig).unwrap());
    }
}
