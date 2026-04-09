//! Hypertree construction for SLH-DSA-SHA2-128s.
//!
//! The hypertree consists of D=7 layers of XMSS trees, each of height H'=9.

use crate::address::Adrs;
use crate::hash::CachedHasher;
use crate::params::*;
use crate::xmss::{self, XmssSig, XMSS_SIG_BYTES};

/// Hypertree signature: D XMSS signatures.
pub struct HypertreeSig {
    pub layers: [XmssSig; D],
}

/// Hypertree signing.
pub fn ht_sign(
    hasher: &CachedHasher,
    msg: &[u8; N],
    sk_seed: &[u8; N],
    idx_tree: u64,
    idx_leaf: u32,
) -> HypertreeSig {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);

    let sig0 = xmss::xmss_sign(hasher, msg, sk_seed, idx_leaf, &mut adrs);
    let mut root = xmss::xmss_pk_from_sig(hasher, idx_leaf, &sig0, msg, &mut adrs);

    let mut sigs: Vec<XmssSig> = Vec::with_capacity(D);
    sigs.push(sig0);

    let mut tree = idx_tree;

    for j in 1..D {
        let leaf = (tree & ((1 << H_PRIME) - 1)) as u32;
        tree >>= H_PRIME;

        adrs.set_layer(j as u32);
        adrs.set_tree_address(tree);

        let sig_j = xmss::xmss_sign(hasher, &root, sk_seed, leaf, &mut adrs);
        if j < D - 1 {
            root = xmss::xmss_pk_from_sig(hasher, leaf, &sig_j, &root, &mut adrs);
        }
        sigs.push(sig_j);
    }

    HypertreeSig {
        layers: sigs
            .try_into()
            .unwrap_or_else(|_| panic!("wrong number of layers")),
    }
}

/// Hypertree verification.
pub fn ht_verify(
    hasher: &CachedHasher,
    msg: &[u8; N],
    sig: &HypertreeSig,
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8; N],
) -> bool {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);

    let mut root =
        xmss::xmss_pk_from_sig(hasher, idx_leaf, &sig.layers[0], msg, &mut adrs);

    let mut tree = idx_tree;

    for j in 1..D {
        let leaf = (tree & ((1 << H_PRIME) - 1)) as u32;
        tree >>= H_PRIME;

        adrs.set_layer(j as u32);
        adrs.set_tree_address(tree);

        root = xmss::xmss_pk_from_sig(hasher, leaf, &sig.layers[j], &root, &mut adrs);
    }

    root == *pk_root
}

/// Hypertree verification directly from signature bytes (zero-copy).
pub fn ht_verify_bytes(
    hasher: &CachedHasher,
    msg: &[u8; N],
    sig_bytes: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8; N],
) -> bool {
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);

    let mut root = xmss::xmss_pk_from_sig_bytes(
        hasher,
        idx_leaf,
        &sig_bytes[0..XMSS_SIG_BYTES],
        msg,
        &mut adrs,
    );

    let mut tree = idx_tree;

    for j in 1..D {
        let leaf = (tree & ((1 << H_PRIME) - 1)) as u32;
        tree >>= H_PRIME;

        adrs.set_layer(j as u32);
        adrs.set_tree_address(tree);

        let offset = j * XMSS_SIG_BYTES;
        root = xmss::xmss_pk_from_sig_bytes(
            hasher,
            leaf,
            &sig_bytes[offset..offset + XMSS_SIG_BYTES],
            &root,
            &mut adrs,
        );
    }

    root == *pk_root
}

/// Serialize a hypertree signature.
pub fn ht_sig_to_bytes(sig: &HypertreeSig) -> Vec<u8> {
    let mut out = Vec::with_capacity(D * XMSS_SIG_BYTES);
    for layer in &sig.layers {
        out.extend_from_slice(&xmss::xmss_sig_to_bytes(layer));
    }
    out
}

/// Deserialize a hypertree signature.
pub fn ht_sig_from_bytes(data: &[u8]) -> HypertreeSig {
    let layers: [XmssSig; D] = core::array::from_fn(|j| {
        let offset = j * XMSS_SIG_BYTES;
        xmss::xmss_sig_from_bytes(&data[offset..offset + XMSS_SIG_BYTES])
    });
    HypertreeSig { layers }
}
