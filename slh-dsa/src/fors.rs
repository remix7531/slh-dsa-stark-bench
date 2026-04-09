//! FORS few-time signature scheme for SLH-DSA-SHA2-128s.

use crate::address::Adrs;
use crate::hash::CachedHasher;
use crate::params::*;
use crate::wots::base_2b;

/// FORS secret key generation.
fn fors_sk_gen(
    hasher: &CachedHasher,
    sk_seed: &[u8; N],
    adrs: &Adrs,
    idx: u32,
) -> [u8; N] {
    let mut prf_adrs = adrs.to_fors_prf();
    prf_adrs.set_tree_index(idx);
    hasher.prf(&prf_adrs, sk_seed)
}

/// Compute a FORS tree node (recursive).
fn fors_node(
    hasher: &CachedHasher,
    sk_seed: &[u8; N],
    i: u32,
    z: u32,
    adrs: &mut Adrs,
) -> [u8; N] {
    if z == 0 {
        let sk = fors_sk_gen(hasher, sk_seed, adrs, i);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        hasher.f(adrs, &sk)
    } else {
        let lnode = fors_node(hasher, sk_seed, 2 * i, z - 1, adrs);
        let rnode = fors_node(hasher, sk_seed, 2 * i + 1, z - 1, adrs);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        hasher.h(adrs, &lnode, &rnode)
    }
}

/// FORS signature: K trees, each with a secret value and A auth path nodes.
pub struct ForsSig {
    pub trees: [ForsTreeSig; K],
}

pub struct ForsTreeSig {
    pub sk: [u8; N],
    pub auth: [[u8; N]; A],
}

/// FORS signing (Algorithm 15).
pub fn fors_sign(
    hasher: &CachedHasher,
    md: &[u8],
    sk_seed: &[u8; N],
    adrs: &mut Adrs,
) -> ForsSig {
    let indices: [u16; K] = base_2b(md, A);

    let mut trees: [ForsTreeSig; K] = core::array::from_fn(|_| ForsTreeSig {
        sk: [0u8; N],
        auth: [[0u8; N]; A],
    });

    for i in 0..K {
        let idx = indices[i] as u32;
        let base = (i as u32) << A;

        trees[i].sk = fors_sk_gen(hasher, sk_seed, adrs, base + idx);

        for j in 0..A {
            let s = (idx >> j) ^ 1;
            let node_idx = (base >> j) + s;
            trees[i].auth[j] = fors_node(hasher, sk_seed, node_idx, j as u32, adrs);
        }
    }

    ForsSig { trees }
}

/// FORS public key from signature (Algorithm 16).
/// Works with both owned ForsSig and zero-copy ForsSigRef.
pub fn fors_pk_from_sig(
    hasher: &CachedHasher,
    sig: &ForsSig,
    md: &[u8],
    adrs: &mut Adrs,
) -> [u8; N] {
    let indices: [u16; K] = base_2b(md, A);
    let mut roots = [[0u8; N]; K];

    for i in 0..K {
        let idx = indices[i] as u32;
        let base = (i as u32) << A;

        adrs.set_tree_height(0);
        adrs.set_tree_index(base + idx);
        let mut node = hasher.f(adrs, &sig.trees[i].sk);

        let mut cur_idx = base + idx;
        for j in 0..A {
            adrs.set_tree_height((j + 1) as u32);
            cur_idx >>= 1;
            adrs.set_tree_index(cur_idx);
            if (idx >> j) & 1 == 0 {
                node = hasher.h(adrs, &node, &sig.trees[i].auth[j]);
            } else {
                node = hasher.h(adrs, &sig.trees[i].auth[j], &node);
            }
        }

        roots[i] = node;
    }

    let fors_roots_adrs = adrs.to_fors_roots();
    hasher.t(&fors_roots_adrs, &roots)
}

/// FORS public key recovery directly from signature bytes (zero-copy).
/// Avoids deserializing the entire FORS signature into a struct.
pub fn fors_pk_from_sig_bytes(
    hasher: &CachedHasher,
    sig_bytes: &[u8],
    md: &[u8],
    adrs: &mut Adrs,
) -> [u8; N] {
    let indices: [u16; K] = base_2b(md, A);
    let mut roots = [[0u8; N]; K];
    let tree_size = (1 + A) * N;

    for i in 0..K {
        let idx = indices[i] as u32;
        let base = (i as u32) << A;
        let tree_offset = i * tree_size;

        // Read sk directly from bytes
        let sk: &[u8; N] = sig_bytes[tree_offset..tree_offset + N].try_into().unwrap();

        adrs.set_tree_height(0);
        adrs.set_tree_index(base + idx);
        let mut node = hasher.f(adrs, sk);

        let mut cur_idx = base + idx;
        for j in 0..A {
            let auth: &[u8; N] = sig_bytes[tree_offset + (1 + j) * N..tree_offset + (2 + j) * N]
                .try_into()
                .unwrap();

            adrs.set_tree_height((j + 1) as u32);
            cur_idx >>= 1;
            adrs.set_tree_index(cur_idx);
            if (idx >> j) & 1 == 0 {
                node = hasher.h(adrs, &node, auth);
            } else {
                node = hasher.h(adrs, auth, &node);
            }
        }

        roots[i] = node;
    }

    let fors_roots_adrs = adrs.to_fors_roots();
    hasher.t(&fors_roots_adrs, &roots)
}

/// Serialize a FORS signature to bytes.
pub fn fors_sig_to_bytes(sig: &ForsSig) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * (1 + A) * N);
    for tree in &sig.trees {
        out.extend_from_slice(&tree.sk);
        for auth in &tree.auth {
            out.extend_from_slice(auth);
        }
    }
    out
}

/// Deserialize a FORS signature from bytes.
pub fn fors_sig_from_bytes(data: &[u8]) -> ForsSig {
    let mut trees: [ForsTreeSig; K] = core::array::from_fn(|_| ForsTreeSig {
        sk: [0u8; N],
        auth: [[0u8; N]; A],
    });

    let mut offset = 0;
    for tree in &mut trees {
        tree.sk.copy_from_slice(&data[offset..offset + N]);
        offset += N;
        for auth in &mut tree.auth {
            auth.copy_from_slice(&data[offset..offset + N]);
            offset += N;
        }
    }

    ForsSig { trees }
}
