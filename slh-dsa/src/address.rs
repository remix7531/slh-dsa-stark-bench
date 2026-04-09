//! ADRS (Address) structure for SLH-DSA.
//!
//! 32-byte structure used to domain-separate hash calls.
//! Layout (all big-endian):
//!   [0..4]   layer_adrs
//!   [4..8]   tree_adrs_high (always 0 for 128s)
//!   [8..16]  tree_adrs_low
//!   [16..20] type_const
//!   [20..24] field_1 (key_pair / padding)
//!   [24..28] field_2 (chain / tree_height / padding)
//!   [28..32] field_3 (hash_adrs / tree_index / padding)

#[derive(Clone, Copy)]
pub struct Adrs {
    pub bytes: [u8; 32],
}

const WOTS_PK: u32 = 1;
const HASH_TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

impl Default for Adrs {
    fn default() -> Self {
        Self::new()
    }
}

impl Adrs {
    pub fn new() -> Self {
        Adrs { bytes: [0u8; 32] }
    }

    pub fn set_layer(&mut self, layer: u32) {
        self.bytes[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    pub fn set_tree_address(&mut self, tree: u64) {
        self.bytes[4..8].fill(0);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    fn set_type(&mut self, t: u32) {
        self.bytes[16..20].copy_from_slice(&t.to_be_bytes());
        self.bytes[20..32].fill(0);
    }

    /// Set type, preserving key_pair field.
    fn set_type_keep_kp(&mut self, t: u32) {
        let kp = self.get_key_pair();
        self.set_type(t);
        self.set_key_pair(kp);
    }

    fn get_key_pair(&self) -> u32 {
        u32::from_be_bytes(self.bytes[20..24].try_into().unwrap())
    }

    pub fn set_key_pair(&mut self, kp: u32) {
        self.bytes[20..24].copy_from_slice(&kp.to_be_bytes());
    }

    pub fn set_chain(&mut self, chain: u32) {
        self.bytes[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    pub fn set_hash_adrs(&mut self, hash: u32) {
        self.bytes[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    pub fn set_tree_height(&mut self, h: u32) {
        self.bytes[24..28].copy_from_slice(&h.to_be_bytes());
    }

    pub fn set_tree_index(&mut self, idx: u32) {
        self.bytes[28..32].copy_from_slice(&idx.to_be_bytes());
    }

    /// Transition to WotsPrf (type 5). Preserves layer/tree/key_pair.
    pub fn to_wots_prf(&self) -> Self {
        let mut a = *self;
        a.set_type_keep_kp(WOTS_PRF);
        a
    }

    /// Transition to WotsPk (type 1). Preserves layer/tree/key_pair.
    pub fn to_wots_pk(&self) -> Self {
        let mut a = *self;
        a.set_type_keep_kp(WOTS_PK);
        a
    }

    /// Transition to HashTree (type 2). Preserves layer/tree.
    pub fn to_hash_tree(&self) -> Self {
        let mut a = *self;
        a.set_type(HASH_TREE);
        a
    }

    /// Create a ForsTree address (type 3).
    pub fn as_fors_tree(idx_tree: u64, idx_leaf: u32) -> Self {
        let mut a = Adrs::new();
        a.set_type(FORS_TREE);
        a.set_tree_address(idx_tree);
        a.set_key_pair(idx_leaf);
        a
    }

    /// Transition to ForsPrf (type 6). Preserves tree/key_pair.
    pub fn to_fors_prf(&self) -> Self {
        let mut a = *self;
        a.set_type_keep_kp(FORS_PRF);
        a
    }

    /// Transition to ForsRoots (type 4). Preserves tree/key_pair.
    pub fn to_fors_roots(&self) -> Self {
        let mut a = *self;
        a.set_type_keep_kp(FORS_ROOTS);
        a
    }

    /// Compressed address (ADRSc) for SHA-2 constructions: 22 bytes.
    /// ADRSc = ADRS[3] || ADRS[8..16] || ADRS[19] || ADRS[20..32]
    pub fn compress(&self) -> [u8; 22] {
        let mut c = [0u8; 22];
        c[0] = self.bytes[3];
        c[1..9].copy_from_slice(&self.bytes[8..16]);
        c[9] = self.bytes[19];
        c[10..22].copy_from_slice(&self.bytes[20..32]);
        c
    }
}
