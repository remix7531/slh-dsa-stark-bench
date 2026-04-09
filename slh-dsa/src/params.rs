//! SLH-DSA-SHA2-128s parameter set (FIPS 205).
//!
//! Security level 1, SHA-256, "small" signatures.

/// Security parameter: hash output length in bytes.
pub const N: usize = 16;

/// Total tree height.
pub const H: usize = 63;

/// Number of hypertree layers.
pub const D: usize = 7;

/// Height of each XMSS tree (H / D).
pub const H_PRIME: usize = 9;

/// FORS tree height.
pub const A: usize = 12;

/// Number of FORS trees.
pub const K: usize = 14;

/// Winternitz parameter.
pub const W: usize = 16;

/// log2(W).
pub const LOG_W: usize = 4;

/// Number of base-w digits in a WOTS+ message.
pub const WOTS_MSG_LEN: usize = 2 * N; // 32

/// Checksum length in base-w digits.
pub const WOTS_CK_LEN: usize = 3;

/// Total WOTS+ signature length in n-byte chunks.
pub const WOTS_SIG_LEN: usize = WOTS_MSG_LEN + WOTS_CK_LEN; // 35

/// Message digest length in bytes: ceil(K * A / 8).
pub const MD: usize = 21;

/// Index tree bytes: ceil((H - H_PRIME) / 8) = ceil(54/8) = 7.
pub const IDX_TREE_BYTES: usize = 7;

/// Index leaf bytes: ceil(H_PRIME / 8) = ceil(9/8) = 2.
pub const IDX_LEAF_BYTES: usize = 2;

/// Total message hash output length.
pub const M: usize = MD + IDX_TREE_BYTES + IDX_LEAF_BYTES; // 30

/// Signature size in bytes.
pub const SIG_LEN: usize = N + K * (1 + A) * N + D * (WOTS_SIG_LEN + H_PRIME) * N; // 7856

/// Secret key size in bytes.
pub const SK_LEN: usize = 4 * N; // 64

/// Public key size in bytes.
pub const PK_LEN: usize = 2 * N; // 32
