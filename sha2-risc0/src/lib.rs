//! SHA-256 implementation with optional RISC Zero zkVM acceleration.
//!
//! State is stored internally in LE format (risc0-native) so the zkVM
//! accelerator path has zero byte-swap overhead per compression call.

#![no_std]

mod compress;
mod consts;

/// SHA-256 initial state in LE format (each word byte-swapped from standard BE).
const H256_LE: [u32; 8] = [
    0x6a09e667_u32.swap_bytes(),
    0xbb67ae85_u32.swap_bytes(),
    0x3c6ef372_u32.swap_bytes(),
    0xa54ff53a_u32.swap_bytes(),
    0x510e527f_u32.swap_bytes(),
    0x9b05688c_u32.swap_bytes(),
    0x1f83d9ab_u32.swap_bytes(),
    0x5be0cd19_u32.swap_bytes(),
];

/// SHA-256 compression function.
///
/// State is 8 × u32 words in LE format (risc0-native byte order).
pub fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress::compress_block(state, block);
    }
}

/// Compute SHA-256 hash of `data`, returning a 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H256_LE;

    let blocks = data.len() >> 6;
    let remaining = data.len() & 63;

    for i in 0..blocks {
        let block: &[u8; 64] = data[i * 64..][..64].try_into().unwrap();
        compress::compress_block(&mut state, block);
    }

    // Padding
    let total_bits = (data.len() as u64) << 3;
    let mut final_block = [0u8; 64];
    final_block[..remaining].copy_from_slice(&data[blocks * 64..]);
    final_block[remaining] = 0x80;

    if remaining >= 56 {
        compress::compress_block(&mut state, &final_block);
        final_block = [0u8; 64];
    }

    final_block[56..64].copy_from_slice(&total_bits.to_be_bytes());
    compress::compress_block(&mut state, &final_block);

    // State is LE — swap to BE then write as bytes.
    // swap_bytes + to_be_bytes = to_le_bytes
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Return the LE-format initial state (for use by callers who manage state directly).
pub fn init_state() -> [u32; 8] {
    H256_LE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }
}
