//! SHA-256 compression function.
//!
//! Two backends:
//! - Software: pure Rust, no dependencies
//! - RISC Zero: routes through the zkVM SHA-256 accelerator circuit
//!
//! State is stored in LE format (risc0-native) to avoid byte-swapping
//! on every compression call in the zkVM. The software backend swaps
//! to BE for the standard algorithm, then swaps back.

/// Compress a single 64-byte block into the SHA-256 state.
/// State is in LE format (each u32 is byte-swapped from standard SHA-256 BE).
#[inline]
pub fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    #[cfg(all(feature = "risc0", target_os = "zkvm"))]
    risc0_compress(state, block);

    #[cfg(not(all(feature = "risc0", target_os = "zkvm")))]
    software_compress(state, block);
}

/// Software SHA-256 compression.
/// Swaps state LE→BE, runs standard algorithm, swaps back.
#[cfg(not(all(feature = "risc0", target_os = "zkvm")))]
fn software_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    use crate::consts::K32;

    // Convert block bytes to BE u32 message words
    let mut w: [u32; 16] =
        core::array::from_fn(|i| u32::from_be_bytes(block[4 * i..][..4].try_into().unwrap()));

    // Swap state from LE storage to BE for the algorithm
    let mut a = state[0].swap_bytes();
    let mut b = state[1].swap_bytes();
    let mut c = state[2].swap_bytes();
    let mut d = state[3].swap_bytes();
    let mut e = state[4].swap_bytes();
    let mut f = state[5].swap_bytes();
    let mut g = state[6].swap_bytes();
    let mut h = state[7].swap_bytes();

    for i in 0..64 {
        let wi = if i < 16 {
            w[i]
        } else {
            let w15 = w[(i - 15) % 16];
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let w2 = w[(i - 2) % 16];
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            let new_w = w[(i - 16) % 16]
                .wrapping_add(s0)
                .wrapping_add(w[(i - 7) % 16])
                .wrapping_add(s1);
            w[i % 16] = new_w;
            new_w
        };

        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = s1
            .wrapping_add(ch)
            .wrapping_add(K32[i])
            .wrapping_add(wi)
            .wrapping_add(h);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Add back and swap result to LE storage
    state[0] = state[0].swap_bytes().wrapping_add(a).swap_bytes();
    state[1] = state[1].swap_bytes().wrapping_add(b).swap_bytes();
    state[2] = state[2].swap_bytes().wrapping_add(c).swap_bytes();
    state[3] = state[3].swap_bytes().wrapping_add(d).swap_bytes();
    state[4] = state[4].swap_bytes().wrapping_add(e).swap_bytes();
    state[5] = state[5].swap_bytes().wrapping_add(f).swap_bytes();
    state[6] = state[6].swap_bytes().wrapping_add(g).swap_bytes();
    state[7] = state[7].swap_bytes().wrapping_add(h).swap_bytes();
}

/// RISC Zero accelerated SHA-256 compression.
/// State is already in LE format — pass directly to syscall.
/// Block bytes are reinterpreted as u32 words via unaligned read.
#[cfg(all(feature = "risc0", target_os = "zkvm"))]
fn risc0_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    use risc0_zkvm_platform::syscall::sys_sha_compress;

    // Reinterpret block bytes as two [u32; 8] halves.
    // On RISC-V LE, from_ne_bytes is identity — this is just a memcpy
    // to ensure alignment for the syscall.
    let half1: [u32; 8] = 
        unsafe { core::ptr::read_unaligned(block.as_ptr() as *const [u32; 8]) };
    let half2: [u32; 8] =
        unsafe { core::ptr::read_unaligned(block.as_ptr().add(32) as *const [u32; 8]) };

    unsafe {
        sys_sha_compress(
            state as *mut [u32; 8],
            state as *const [u32; 8],
            &half1 as *const [u32; 8],
            &half2 as *const [u32; 8],
        );
    }
}
