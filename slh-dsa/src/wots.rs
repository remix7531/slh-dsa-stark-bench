//! WOTS+ one-time signature scheme for SLH-DSA-SHA2-128s.

#![allow(clippy::needless_range_loop)]

use crate::address::Adrs;
use crate::hash::CachedHasher;
use crate::params::*;

/// Convert byte string to base-2^b digits (FIPS 205 Algorithm 3).
/// Reads bits MSB-first, extracting b-bit chunks.
/// Returns a fixed-size array to avoid heap allocation.
pub fn base_2b<const OUT_LEN: usize>(x: &[u8], b: usize) -> [u16; OUT_LEN] {
    let mask = (1u32 << b) - 1;
    let mut result = [0u16; OUT_LEN];
    let mut in_idx = 0usize;
    let mut bits = 0u32;
    let mut total = 0u32;

    for r in result.iter_mut() {
        while bits < b as u32 {
            total = (total << 8) | x[in_idx] as u32;
            in_idx += 1;
            bits += 8;
        }
        bits -= b as u32;
        *r = ((total >> bits) & mask) as u16;
    }
    result
}

/// WOTS+ chain computation (Algorithm 4).
pub fn chain(
    hasher: &CachedHasher,
    x: &[u8; N],
    start: u32,
    steps: u32,
    adrs: &mut Adrs,
) -> [u8; N] {
    let mut tmp = *x;
    for j in start..start + steps {
        adrs.set_hash_adrs(j);
        tmp = hasher.f(adrs, &tmp);
    }
    tmp
}

/// Compute WOTS+ message digits with checksum. Returns [u16; WOTS_SIG_LEN].
fn wots_msg_csum(msg: &[u8; N]) -> [u16; WOTS_SIG_LEN] {
    let msg_digits: [u16; WOTS_MSG_LEN] = base_2b(msg, LOG_W);

    let mut csum: u32 = 0;
    for &d in &msg_digits {
        csum += (W as u32 - 1) - d as u32;
    }
    csum <<= 4;

    let csum_bytes = (csum as u16).to_be_bytes();
    let csum_digits: [u16; WOTS_CK_LEN] = base_2b(&csum_bytes, LOG_W);

    let mut result = [0u16; WOTS_SIG_LEN];
    result[..WOTS_MSG_LEN].copy_from_slice(&msg_digits);
    result[WOTS_MSG_LEN..].copy_from_slice(&csum_digits);
    result
}

/// Generate WOTS+ public key (Algorithm 5).
pub fn wots_pk_gen(
    hasher: &CachedHasher,
    sk_seed: &[u8; N],
    adrs: &mut Adrs,
) -> [u8; N] {
    let mut sk_adrs = adrs.to_wots_prf();
    let mut tmp = [[0u8; N]; WOTS_SIG_LEN];

    for i in 0..WOTS_SIG_LEN {
        sk_adrs.set_chain(i as u32);
        adrs.set_chain(i as u32);
        let sk = hasher.prf(&sk_adrs, sk_seed);
        tmp[i] = chain(hasher, &sk, 0, (W - 1) as u32, adrs);
    }

    let pk_adrs = adrs.to_wots_pk();
    hasher.t(&pk_adrs, &tmp)
}

/// WOTS+ signing (Algorithm 6).
pub fn wots_sign(
    hasher: &CachedHasher,
    msg: &[u8; N],
    sk_seed: &[u8; N],
    adrs: &mut Adrs,
) -> [[u8; N]; WOTS_SIG_LEN] {
    let mut sig = [[0u8; N]; WOTS_SIG_LEN];
    let msg_csum = wots_msg_csum(msg);

    let mut sk_adrs = adrs.to_wots_prf();

    for i in 0..WOTS_SIG_LEN {
        sk_adrs.set_chain(i as u32);
        adrs.set_chain(i as u32);
        let sk = hasher.prf(&sk_adrs, sk_seed);
        sig[i] = chain(hasher, &sk, 0, msg_csum[i] as u32, adrs);
    }

    sig
}

/// WOTS+ public key from signature (Algorithm 7).
pub fn wots_pk_from_sig(
    hasher: &CachedHasher,
    sig: &[[u8; N]; WOTS_SIG_LEN],
    msg: &[u8; N],
    adrs: &mut Adrs,
) -> [u8; N] {
    let msg_csum = wots_msg_csum(msg);

    let mut tmp = [[0u8; N]; WOTS_SIG_LEN];
    for i in 0..WOTS_SIG_LEN {
        adrs.set_chain(i as u32);
        let start = msg_csum[i] as u32;
        let steps = (W as u32 - 1) - start;
        tmp[i] = chain(hasher, &sig[i], start, steps, adrs);
    }

    let pk_adrs = adrs.to_wots_pk();
    hasher.t(&pk_adrs, &tmp)
}
