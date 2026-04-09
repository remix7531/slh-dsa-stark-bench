//! SHA-256 based tweakable hash functions for SLH-DSA-SHA2-128s.
//!
//! All functions use a "cached hasher" pattern: the SHA-256 compression function
//! is pre-run on PK.seed || zeros(64-N) so the first 64-byte block state is cached.
//! Subsequent calls clone the state and continue compressing additional data.

use sha2_risc0::{compress256, init_state, sha256};

use crate::address::Adrs;
use crate::params::N;

/// Pre-computed SHA-256 state after processing PK.seed || 0^48 (one 64-byte block).
#[derive(Clone)]
pub struct CachedHasher {
    state: [u32; 8],
}

/// Compress data with cached state, finalize, return first N bytes.
/// Optimized for inputs that fit in a single block (< 56 bytes after prefix).
#[inline(always)]
fn hash_cached_n(state: &[u32; 8], data: &[u8]) -> [u8; N] {
    let mut st = *state;
    let total_len: u64 = (64 + data.len()) as u64;

    // For F/H/PRF: data is 38 or 54 bytes — always fits in one block
    // For safety, handle the multi-block case too
    let mut offset = 0;
    while offset + 64 <= data.len() {
        let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
        compress256(&mut st, &[block]);
        offset += 64;
    }

    let remaining = data.len() - offset;
    let mut last_block = [0u8; 64];
    last_block[..remaining].copy_from_slice(&data[offset..]);
    last_block[remaining] = 0x80;

    let bit_len = total_len * 8;
    if remaining < 56 {
        last_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress256(&mut st, &[last_block]);
    } else {
        compress256(&mut st, &[last_block]);
        let mut extra = [0u8; 64];
        extra[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress256(&mut st, &[extra]);
    }

    // Only convert N/4 = 4 words instead of all 8
    let mut out = [0u8; N];
    for i in 0..N / 4 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&st[i].to_le_bytes());
    }
    out
}

impl CachedHasher {
    pub fn new(pk_seed: &[u8; N]) -> Self {
        let mut block = [0u8; 64];
        block[..N].copy_from_slice(pk_seed);

        let mut state = init_state();
        compress256(&mut state, &[block]);
        CachedHasher { state }
    }

    /// F(PK.seed, ADRS, M1) — single n-byte block input.
    #[inline]
    pub fn f(&self, adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
        let mut data = [0u8; 22 + N];
        data[..22].copy_from_slice(&adrs.compress());
        data[22..].copy_from_slice(m1);
        hash_cached_n(&self.state, &data)
    }

    /// H(PK.seed, ADRS, M1, M2) — two n-byte block inputs (Merkle node).
    #[inline]
    pub fn h(&self, adrs: &Adrs, m1: &[u8; N], m2: &[u8; N]) -> [u8; N] {
        let mut data = [0u8; 22 + 2 * N];
        data[..22].copy_from_slice(&adrs.compress());
        data[22..22 + N].copy_from_slice(m1);
        data[22 + N..].copy_from_slice(m2);
        hash_cached_n(&self.state, &data)
    }

    /// T_l(PK.seed, ADRS, M) — variable-length input (l n-byte blocks).
    pub fn t(&self, adrs: &Adrs, blocks: &[[u8; N]]) -> [u8; N] {
        let adrs_c = adrs.compress();
        let total_data_len = 22 + blocks.len() * N;
        let total_len: u64 = (64 + total_data_len) as u64;
        let bit_len = total_len * 8;

        let mut state = self.state;
        let mut buf = [0u8; 64];

        buf[..22].copy_from_slice(&adrs_c);
        let mut buf_len = 22usize;

        for block in blocks {
            let mut src_off = 0;
            while src_off < N {
                let space = 64 - buf_len;
                let to_copy = core::cmp::min(space, N - src_off);
                buf[buf_len..buf_len + to_copy]
                    .copy_from_slice(&block[src_off..src_off + to_copy]);
                buf_len += to_copy;
                src_off += to_copy;

                if buf_len == 64 {
                    compress256(&mut state, &[buf]);
                    buf = [0u8; 64];
                    buf_len = 0;
                }
            }
        }

        buf[buf_len] = 0x80;
        buf_len += 1;

        if buf_len <= 56 {
            buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
            compress256(&mut state, &[buf]);
        } else {
            compress256(&mut state, &[buf]);
            let mut extra = [0u8; 64];
            extra[56..64].copy_from_slice(&bit_len.to_be_bytes());
            compress256(&mut state, &[extra]);
        }

        let mut output = [0u8; N];
        for i in 0..N / 4 {
            output[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
        }
        output
    }

    /// PRF(PK.seed, SK.seed, ADRS).
    #[inline]
    pub fn prf(&self, adrs: &Adrs, sk_seed: &[u8; N]) -> [u8; N] {
        let mut data = [0u8; 22 + N];
        data[..22].copy_from_slice(&adrs.compress());
        data[22..].copy_from_slice(sk_seed);
        hash_cached_n(&self.state, &data)
    }
}

/// PRF_msg(SK.prf, opt_rand, M) — HMAC-SHA-256 based.
pub fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], msg: &[u8]) -> [u8; N] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..N {
        ipad[i] ^= sk_prf[i];
        opad[i] ^= sk_prf[i];
    }

    let mut state = init_state();
    compress256(&mut state, &[ipad]);

    let inner_data_len = N + msg.len();
    let total_len: u64 = (64 + inner_data_len) as u64;

    let mut buf = [0u8; 64];
    buf[..N].copy_from_slice(opt_rand);
    let mut buf_len = N;

    let mut msg_off = 0;
    while msg_off < msg.len() {
        let space = 64 - buf_len;
        let to_copy = core::cmp::min(space, msg.len() - msg_off);
        buf[buf_len..buf_len + to_copy].copy_from_slice(&msg[msg_off..msg_off + to_copy]);
        buf_len += to_copy;
        msg_off += to_copy;

        if buf_len == 64 {
            compress256(&mut state, &[buf]);
            buf = [0u8; 64];
            buf_len = 0;
        }
    }

    buf[buf_len] = 0x80;
    buf_len += 1;
    let bit_len = total_len * 8;
    if buf_len <= 56 {
        buf[buf_len..56].fill(0);
        buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress256(&mut state, &[buf]);
    } else {
        buf[buf_len..64].fill(0);
        compress256(&mut state, &[buf]);
        let mut extra = [0u8; 64];
        extra[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress256(&mut state, &[extra]);
    }

    let mut inner_hash = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        inner_hash[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let mut outer_data = [0u8; 96];
    outer_data[..64].copy_from_slice(&opad);
    outer_data[64..96].copy_from_slice(&inner_hash);
    truncate_n(&sha256(&outer_data))
}

/// H_msg(R, PK.seed, PK.root, M) — MGF1-SHA-256 based message hash.
pub fn h_msg(
    r: &[u8; N],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg: &[u8],
) -> [u8; crate::params::M] {
    let mut state = init_state();
    let mut buf = [0u8; 64];
    buf[..N].copy_from_slice(r);
    buf[N..2 * N].copy_from_slice(pk_seed);
    buf[2 * N..3 * N].copy_from_slice(pk_root);
    let first_msg = core::cmp::min(16, msg.len());
    buf[48..48 + first_msg].copy_from_slice(&msg[..first_msg]);

    let total_len: u64 = (48 + msg.len()) as u64;
    let mut buf_len = 48 + first_msg;
    let mut msg_off = first_msg;

    if buf_len == 64 {
        compress256(&mut state, &[buf]);
        buf = [0u8; 64];
        buf_len = 0;
    }

    while msg_off < msg.len() {
        let space = 64 - buf_len;
        let to_copy = core::cmp::min(space, msg.len() - msg_off);
        buf[buf_len..buf_len + to_copy].copy_from_slice(&msg[msg_off..msg_off + to_copy]);
        buf_len += to_copy;
        msg_off += to_copy;

        if buf_len == 64 {
            compress256(&mut state, &[buf]);
            buf = [0u8; 64];
            buf_len = 0;
        }
    }

    buf[buf_len] = 0x80;
    buf_len += 1;
    let bit_len = total_len * 8;
    if buf_len <= 56 {
        buf[buf_len..56].fill(0);
        buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress256(&mut state, &[buf]);
    } else {
        buf[buf_len..64].fill(0);
        compress256(&mut state, &[buf]);
        let mut extra = [0u8; 64];
        extra[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress256(&mut state, &[extra]);
    }

    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let mut seed = [0u8; N + N + 32];
    seed[0..N].copy_from_slice(r);
    seed[N..2 * N].copy_from_slice(pk_seed);
    seed[2 * N..].copy_from_slice(&digest);

    mgf1_sha256(&seed)
}

/// MGF1-SHA-256: produces M=30 bytes of output.
fn mgf1_sha256(seed: &[u8; N + N + 32]) -> [u8; crate::params::M] {
    let mut input = [0u8; N + N + 32 + 4];
    input[..seed.len()].copy_from_slice(seed);
    let block = sha256(&input);

    let mut result = [0u8; crate::params::M];
    result.copy_from_slice(&block[..crate::params::M]);
    result
}

/// Truncate a 32-byte SHA-256 output to N bytes.
fn truncate_n(hash: &[u8; 32]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&hash[..N]);
    out
}
