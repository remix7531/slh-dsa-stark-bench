/// Generate a STARK proof that all SLH-DSA signatures are valid.
///
/// Usage: prove -k <pubkeys.json> -m <messages.json> -s <signatures.json> -o <proof.bin> [-v]

use cli::util::{arg_value, fmt_duration, has_flag, rel_path};
use methods::{VERIFY_SIGNATURES_ELF, VERIFY_SIGNATURES_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use slh_dsa::{PublicKey, Signature};
use std::process::ExitCode;
use std::time::Instant;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "-h") || has_flag(&args, "--help") {
        eprintln!("Usage: prove -k <pubkeys.json> -m <messages.json> -s <signatures.json> -o <proof.bin> [-v]");
        return ExitCode::SUCCESS;
    }

    let verbose = has_flag(&args, "-v") || has_flag(&args, "--verbose");

    let pubkeys_path = match arg_value(&args, "-k") {
        Some(p) => p,
        None => {
            eprintln!("Usage: prove -k <pubkeys.json> -m <messages.json> -s <signatures.json> -o <proof.bin> [-v]");
            return ExitCode::FAILURE;
        }
    };
    let messages_path = match arg_value(&args, "-m") {
        Some(p) => p,
        None => { eprintln!("Error: missing -m <messages.json>"); return ExitCode::FAILURE; }
    };
    let sigs_path = match arg_value(&args, "-s") {
        Some(p) => p,
        None => { eprintln!("Error: missing -s <signatures.json>"); return ExitCode::FAILURE; }
    };
    let proof_path = match arg_value(&args, "-o") {
        Some(p) => p,
        None => { eprintln!("Error: missing -o <proof.bin>"); return ExitCode::FAILURE; }
    };

    // Load inputs
    let pubkeys_json: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&pubkeys_path).unwrap()).unwrap();
    let messages: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&messages_path).unwrap()).unwrap();
    let sig_hexes: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&sigs_path).unwrap()).unwrap();

    let n = messages.len();
    if n != pubkeys_json.len() {
        eprintln!("Error: {} messages but {} public keys", n, pubkeys_json.len());
        return ExitCode::FAILURE;
    }
    if n != sig_hexes.len() {
        eprintln!("Error: {} messages but {} signatures", n, sig_hexes.len());
        return ExitCode::FAILURE;
    }

    // Parse
    let mut msg_bytes: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut public_keys: Vec<PublicKey> = Vec::with_capacity(n);
    let mut signatures: Vec<Signature> = Vec::with_capacity(n);

    for i in 0..n {
        msg_bytes.push(messages[i].as_bytes().to_vec());

        let pk_hex = pubkeys_json[i]["public_key"].as_str().unwrap();
        let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
        public_keys.push(PublicKey { bytes: pk });

        let sig_raw: Vec<u8> = hex::decode(&sig_hexes[i]).unwrap();
        let mut sig = Signature { bytes: [0u8; 7856] };
        sig.bytes.copy_from_slice(&sig_raw);
        signatures.push(sig);
    }

    // Build executor environment
    let n32 = n as u32;
    let mut env_builder = ExecutorEnv::builder();
    env_builder.write(&n32).unwrap();
    for i in 0..n {
        env_builder.write(&msg_bytes[i]).unwrap();
        env_builder.write(&public_keys[i]).unwrap();
        env_builder.write(&signatures[i]).unwrap();
    }
    let env = env_builder.build().unwrap();

    // Prove
    let prove_start = Instant::now();
    let prover = default_prover();
    let prove_info = match prover.prove_with_opts(env, VERIFY_SIGNATURES_ELF, &ProverOpts::succinct()) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error: proof generation failed: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let prove_time = prove_start.elapsed();
    let receipt = prove_info.receipt;

    // Verify locally
    if let Err(e) = receipt.verify(VERIFY_SIGNATURES_ID) {
        eprintln!("Error: receipt verification failed: {}", e);
        return ExitCode::FAILURE;
    }

    // Save proof
    let receipt_bytes = bincode::serialize(&receipt).unwrap();
    std::fs::write(&proof_path, &receipt_bytes).unwrap();

    if verbose {
        eprintln!("Proof time:  {}", fmt_duration(prove_time));
        eprintln!("Proof size:  {} bytes ({:.1} KiB)", receipt_bytes.len(), receipt_bytes.len() as f64 / 1024.0);
        eprintln!("Proof file:  {}", rel_path(&proof_path));
    }

    ExitCode::SUCCESS
}
