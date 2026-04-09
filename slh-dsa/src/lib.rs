//! SLH-DSA-SHA2-128s — simplified, standalone implementation.
//!
//! Hardcoded for the SHA2-128s parameter set (FIPS 205).
//! Only dependency: sha2_fv (SHA-256).

pub mod address;
pub mod fors;
pub mod hash;
pub mod hypertree;
pub mod params;
pub mod wots;
pub mod xmss;

use address::Adrs;
use hash::CachedHasher;
use params::*;

use serde::{Deserialize, Serialize};

/// Public key: PK.seed || PK.root (32 bytes).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub bytes: [u8; PK_LEN],
}

/// Secret key: SK.seed || SK.prf || PK.seed || PK.root (64 bytes).
#[derive(Clone)]
pub struct SecretKey {
    pub bytes: [u8; SK_LEN],
}

/// Signature (7856 bytes).
#[derive(Clone)]
pub struct Signature {
    pub bytes: [u8; SIG_LEN],
}

// Implement Serialize/Deserialize manually for Signature since arrays > 32
// don't auto-derive.
impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Use Vec<u8> serialization for bincode compatibility (not serialize_bytes)
        self.bytes.to_vec().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != SIG_LEN {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes, got {}",
                SIG_LEN,
                bytes.len()
            )));
        }
        let mut sig = Signature {
            bytes: [0u8; SIG_LEN],
        };
        sig.bytes.copy_from_slice(&bytes);
        Ok(sig)
    }
}

impl SecretKey {
    fn sk_seed(&self) -> &[u8; N] {
        self.bytes[0..N].try_into().unwrap()
    }
    fn sk_prf(&self) -> &[u8; N] {
        self.bytes[N..2 * N].try_into().unwrap()
    }
    fn pk_seed(&self) -> &[u8; N] {
        self.bytes[2 * N..3 * N].try_into().unwrap()
    }
    fn pk_root(&self) -> &[u8; N] {
        self.bytes[3 * N..4 * N].try_into().unwrap()
    }
}

impl PublicKey {
    fn pk_seed(&self) -> &[u8; N] {
        self.bytes[0..N].try_into().unwrap()
    }
    fn pk_root(&self) -> &[u8; N] {
        self.bytes[N..2 * N].try_into().unwrap()
    }
}

/// Key generation from a 48-byte seed.
///
/// seed layout: SK.seed (16) || SK.prf (16) || PK.seed (16)
pub fn keygen(seed: &[u8; 3 * N]) -> (PublicKey, SecretKey) {
    let sk_seed: &[u8; N] = seed[0..N].try_into().unwrap();
    let sk_prf: &[u8; N] = seed[N..2 * N].try_into().unwrap();
    let pk_seed: &[u8; N] = seed[2 * N..3 * N].try_into().unwrap();

    let hasher = CachedHasher::new(pk_seed);

    // Compute root of top-layer XMSS tree
    let mut adrs = Adrs::new();
    adrs.set_layer((D - 1) as u32);
    let pk_root = xmss::xmss_node(&hasher, sk_seed, 0, H_PRIME as u32, &mut adrs);

    let mut sk_bytes = [0u8; SK_LEN];
    sk_bytes[0..N].copy_from_slice(sk_seed);
    sk_bytes[N..2 * N].copy_from_slice(sk_prf);
    sk_bytes[2 * N..3 * N].copy_from_slice(pk_seed);
    sk_bytes[3 * N..4 * N].copy_from_slice(&pk_root);

    let mut pk_bytes = [0u8; PK_LEN];
    pk_bytes[0..N].copy_from_slice(pk_seed);
    pk_bytes[N..2 * N].copy_from_slice(&pk_root);

    (
        PublicKey { bytes: pk_bytes },
        SecretKey { bytes: sk_bytes },
    )
}

/// Sign a message. Deterministic (uses PK.seed as opt_rand).
pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    let hasher = CachedHasher::new(sk.pk_seed());

    // Context wrapping: 0x00 || 0x00 || msg (empty context, pure signing)
    let mut msg_with_ctx = Vec::with_capacity(2 + msg.len());
    msg_with_ctx.push(0x00);
    msg_with_ctx.push(0x00);
    msg_with_ctx.extend_from_slice(msg);

    // Deterministic randomizer
    let r = hash::prf_msg(sk.sk_prf(), sk.pk_seed(), &msg_with_ctx);

    // Message hash
    let digest = hash::h_msg(&r, sk.pk_seed(), sk.pk_root(), &msg_with_ctx);

    // Split digest into (md, idx_tree, idx_leaf)
    let (md, idx_tree, idx_leaf) = split_digest(&digest);

    // FORS signature
    let mut fors_adrs = Adrs::as_fors_tree(idx_tree, idx_leaf);
    let fors_sig = fors::fors_sign(&hasher, &md, sk.sk_seed(), &mut fors_adrs);

    // Compute FORS public key
    let mut fors_adrs2 = Adrs::as_fors_tree(idx_tree, idx_leaf);
    let fors_pk = fors::fors_pk_from_sig(&hasher, &fors_sig, &md, &mut fors_adrs2);

    // Hypertree signature over FORS public key
    let ht_sig = hypertree::ht_sign(&hasher, &fors_pk, sk.sk_seed(), idx_tree, idx_leaf);

    // Assemble signature: R || FORS_SIG || HT_SIG
    let mut sig_bytes = [0u8; SIG_LEN];
    sig_bytes[0..N].copy_from_slice(&r);

    let fors_bytes = fors::fors_sig_to_bytes(&fors_sig);
    let fors_end = N + fors_bytes.len();
    sig_bytes[N..fors_end].copy_from_slice(&fors_bytes);

    let ht_bytes = hypertree::ht_sig_to_bytes(&ht_sig);
    sig_bytes[fors_end..fors_end + ht_bytes.len()].copy_from_slice(&ht_bytes);

    Signature { bytes: sig_bytes }
}

/// Verify a signature. Returns true if valid.
/// Uses zero-copy deserialization — works directly from the signature bytes
/// without allocating intermediate structs.
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let hasher = CachedHasher::new(pk.pk_seed());

    // Context wrapping: 0x00 || 0x00 || msg
    let mut msg_with_ctx = Vec::with_capacity(2 + msg.len());
    msg_with_ctx.push(0x00);
    msg_with_ctx.push(0x00);
    msg_with_ctx.extend_from_slice(msg);

    // Parse R from signature header
    let r: [u8; N] = sig.bytes[0..N].try_into().unwrap();
    let fors_sig_start = N;
    let fors_sig_end = N + K * (1 + A) * N;
    let ht_sig_start = fors_sig_end;

    // Message hash
    let digest = hash::h_msg(&r, pk.pk_seed(), pk.pk_root(), &msg_with_ctx);
    let (md, idx_tree, idx_leaf) = split_digest(&digest);

    // FORS public key recovery (zero-copy from sig bytes)
    let mut fors_adrs = Adrs::as_fors_tree(idx_tree, idx_leaf);
    let fors_pk = fors::fors_pk_from_sig_bytes(
        &hasher,
        &sig.bytes[fors_sig_start..fors_sig_end],
        &md,
        &mut fors_adrs,
    );

    // Hypertree verification (zero-copy from sig bytes)
    hypertree::ht_verify_bytes(
        &hasher,
        &fors_pk,
        &sig.bytes[ht_sig_start..],
        idx_tree,
        idx_leaf,
        pk.pk_root(),
    )
}

/// Split the 30-byte message digest into (md[21], idx_tree[54-bit], idx_leaf[9-bit]).
fn split_digest(digest: &[u8; M]) -> ([u8; MD], u64, u32) {
    let mut md = [0u8; MD];
    md.copy_from_slice(&digest[0..MD]);

    // idx_tree: 7 bytes (56 bits), mask to 54 bits
    let mut tree_bytes = [0u8; 8];
    tree_bytes[1..8].copy_from_slice(&digest[MD..MD + IDX_TREE_BYTES]);
    let idx_tree = u64::from_be_bytes(tree_bytes) & ((1u64 << (H - H_PRIME)) - 1);

    // idx_leaf: 2 bytes (16 bits), mask to 9 bits
    let mut leaf_bytes = [0u8; 4];
    leaf_bytes[2..4].copy_from_slice(&digest[MD + IDX_TREE_BYTES..MD + IDX_TREE_BYTES + IDX_LEAF_BYTES]);
    let idx_leaf = u32::from_be_bytes(leaf_bytes) & ((1u32 << H_PRIME) - 1);

    (md, idx_tree, idx_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        // Deterministic seed
        let mut seed = [0u8; 3 * N];
        for i in 0..seed.len() {
            seed[i] = i as u8;
        }

        let (pk, sk) = keygen(&seed);
        let msg = b"Hello, SLH-DSA!";
        let sig = sign(&sk, msg);

        assert!(verify(&pk, msg, &sig), "signature verification failed");

        // Verify wrong message fails
        assert!(!verify(&pk, b"wrong message", &sig), "wrong message should fail");
    }
}
