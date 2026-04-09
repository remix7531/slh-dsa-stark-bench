/// zkVM guest program: verifies N SLH-DSA-SHA2-128s signatures.
///
/// When N=0, runs SHA-256 microbenchmarks instead.

use risc0_zkvm::guest::env;
use slh_dsa::{verify, PublicKey, Signature};

fn main() {
    let n: u32 = env::read();

    if n == 0 {
        sha256_benchmark();
        env::commit(&0u32);
        env::commit(&Vec::<Vec<u8>>::new());
        env::commit(&Vec::<PublicKey>::new());
        return;
    }

    let start_cycles = env::cycle_count();

    let mut messages: Vec<Vec<u8>> = Vec::with_capacity(n as usize);
    let mut public_keys: Vec<PublicKey> = Vec::with_capacity(n as usize);

    for i in 0..n {
        let msg: Vec<u8> = env::read();
        let pk: PublicKey = env::read();
        let sig: Signature = env::read();

        let per_sig_start = env::cycle_count();
        let valid = verify(&pk, &msg, &sig);
        let per_sig_end = env::cycle_count();

        if !valid {
            panic!("Signature {} verification failed", i + 1);
        }

        eprintln!(
            "Signature {} verified in {} cycles",
            i + 1,
            per_sig_end - per_sig_start
        );

        messages.push(msg);
        public_keys.push(pk);
    }

    let total_cycles = env::cycle_count() - start_cycles;
    eprintln!(
        "All {} signatures verified. Total cycles: {}, per signature: {}",
        n,
        total_cycles,
        total_cycles / n as u64
    );

    env::commit(&n);
    env::commit(&messages);
    env::commit(&public_keys);
}

fn sha256_benchmark() {
    use sha2_risc0::{compress256, init_state};

    let block = [0u8; 64];
    let mut state = init_state();

    // Warm up
    compress256(&mut state, &[block]);

    // Single compression
    let c0 = env::cycle_count();
    compress256(&mut state, &[block]);
    let c1 = env::cycle_count();
    eprintln!("1 SHA-256 compression: {} cycles", c1 - c0);

    // 10 compressions
    let c0 = env::cycle_count();
    for _ in 0..10 {
        compress256(&mut state, &[block]);
    }
    let c1 = env::cycle_count();
    eprintln!("10 SHA-256 compressions: {} cycles ({}/each)", c1 - c0, (c1 - c0) / 10);

    // 100 compressions
    let c0 = env::cycle_count();
    for _ in 0..100 {
        compress256(&mut state, &[block]);
    }
    let c1 = env::cycle_count();
    eprintln!("100 SHA-256 compressions: {} cycles ({}/each)", c1 - c0, (c1 - c0) / 100);

    // 1000 compressions
    let c0 = env::cycle_count();
    for _ in 0..1000 {
        compress256(&mut state, &[block]);
    }
    let c1 = env::cycle_count();
    eprintln!("1000 SHA-256 compressions: {} cycles ({}/each)", c1 - c0, (c1 - c0) / 1000);
}
