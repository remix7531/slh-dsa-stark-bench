//! XMSS tree construction and signing for SLH-DSA-SHA2-128s.

#![allow(clippy::needless_range_loop)]

use crate::address::Adrs;
use crate::hash::CachedHasher;
use crate::params::*;
use crate::wots;

/// XMSS signature: WOTS+ signature + authentication path.
pub struct XmssSig {
    pub wots_sig: [[u8; N]; WOTS_SIG_LEN],
    pub auth: [[u8; N]; H_PRIME],
}

/// Size of one XMSS signature in bytes.
pub const XMSS_SIG_BYTES: usize = (WOTS_SIG_LEN + H_PRIME) * N;

/// Compute an XMSS tree node (recursive).
pub fn xmss_node(
    hasher: &CachedHasher,
    sk_seed: &[u8; N],
    node: u32,
    height: u32,
    adrs: &mut Adrs,
) -> [u8; N] {
    if height == 0 {
        adrs.set_key_pair(node);
        wots::wots_pk_gen(hasher, sk_seed, adrs)
    } else {
        let lnode = xmss_node(hasher, sk_seed, 2 * node, height - 1, adrs);
        let rnode = xmss_node(hasher, sk_seed, 2 * node + 1, height - 1, adrs);
        let mut tree_adrs = adrs.to_hash_tree();
        tree_adrs.set_tree_height(height);
        tree_adrs.set_tree_index(node);
        hasher.h(&tree_adrs, &lnode, &rnode)
    }
}

/// XMSS signing (Algorithm 10/11).
pub fn xmss_sign(
    hasher: &CachedHasher,
    msg: &[u8; N],
    sk_seed: &[u8; N],
    idx: u32,
    adrs: &mut Adrs,
) -> XmssSig {
    adrs.set_key_pair(idx);
    let wots_sig = wots::wots_sign(hasher, msg, sk_seed, adrs);

    let mut auth = [[0u8; N]; H_PRIME];
    let mut k = idx;
    for j in 0..H_PRIME {
        let sibling = k ^ 1;
        auth[j] = xmss_node(hasher, sk_seed, sibling, j as u32, adrs);
        k >>= 1;
    }

    XmssSig { wots_sig, auth }
}

/// Compute XMSS root from signature (Algorithm 12).
pub fn xmss_pk_from_sig(
    hasher: &CachedHasher,
    idx: u32,
    sig: &XmssSig,
    msg: &[u8; N],
    adrs: &mut Adrs,
) -> [u8; N] {
    adrs.set_key_pair(idx);
    let mut node = wots::wots_pk_from_sig(hasher, &sig.wots_sig, msg, adrs);

    let mut tree_adrs = adrs.to_hash_tree();
    let mut k = idx;
    for j in 0..H_PRIME {
        tree_adrs.set_tree_height((j + 1) as u32);
        k >>= 1;
        tree_adrs.set_tree_index(k);
        if (idx >> j) & 1 == 0 {
            node = hasher.h(&tree_adrs, &node, &sig.auth[j]);
        } else {
            node = hasher.h(&tree_adrs, &sig.auth[j], &node);
        }
    }

    node
}

/// Compute XMSS root from signature bytes (zero-copy).
pub fn xmss_pk_from_sig_bytes(
    hasher: &CachedHasher,
    idx: u32,
    sig_bytes: &[u8],
    msg: &[u8; N],
    adrs: &mut Adrs,
) -> [u8; N] {
    // Parse WOTS+ sig as references into the byte slice
    let mut wots_sig = [[0u8; N]; WOTS_SIG_LEN];
    for i in 0..WOTS_SIG_LEN {
        wots_sig[i].copy_from_slice(&sig_bytes[i * N..(i + 1) * N]);
    }

    adrs.set_key_pair(idx);
    let mut node = wots::wots_pk_from_sig(hasher, &wots_sig, msg, adrs);

    let auth_offset = WOTS_SIG_LEN * N;
    let mut tree_adrs = adrs.to_hash_tree();
    let mut k = idx;
    for j in 0..H_PRIME {
        let auth: &[u8; N] = sig_bytes[auth_offset + j * N..auth_offset + (j + 1) * N]
            .try_into()
            .unwrap();
        tree_adrs.set_tree_height((j + 1) as u32);
        k >>= 1;
        tree_adrs.set_tree_index(k);
        if (idx >> j) & 1 == 0 {
            node = hasher.h(&tree_adrs, &node, auth);
        } else {
            node = hasher.h(&tree_adrs, auth, &node);
        }
    }

    node
}

/// Serialize an XMSS signature.
pub fn xmss_sig_to_bytes(sig: &XmssSig) -> Vec<u8> {
    let mut out = Vec::with_capacity(XMSS_SIG_BYTES);
    for chunk in &sig.wots_sig {
        out.extend_from_slice(chunk);
    }
    for auth in &sig.auth {
        out.extend_from_slice(auth);
    }
    out
}

/// Deserialize an XMSS signature.
pub fn xmss_sig_from_bytes(data: &[u8]) -> XmssSig {
    let mut wots_sig = [[0u8; N]; WOTS_SIG_LEN];
    let mut auth = [[0u8; N]; H_PRIME];

    let mut offset = 0;
    for chunk in &mut wots_sig {
        chunk.copy_from_slice(&data[offset..offset + N]);
        offset += N;
    }
    for a in &mut auth {
        a.copy_from_slice(&data[offset..offset + N]);
        offset += N;
    }

    XmssSig { wots_sig, auth }
}
