/// Verify SLH-DSA signatures — either directly or via a STARK proof.
///
/// Usage:
///   verify -s <signatures.json> -k <pubkeys.json> -m <messages.json> [-v]
///   verify -p <proof.bin> -k <pubkeys.json> -m <messages.json> [-v]

use cli::util::{arg_value, fmt_duration, has_flag};
use slh_dsa::PublicKey;
use std::process::ExitCode;
use std::time::Instant;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "-h") || has_flag(&args, "--help") {
        eprintln!("Usage:");
        eprintln!("  verify -s <signatures.json> -k <pubkeys.json> -m <messages.json> [-v]");
        eprintln!("  verify -p <proof.bin> -k <pubkeys.json> -m <messages.json> [-v]");
        return ExitCode::SUCCESS;
    }

    let verbose = has_flag(&args, "-v") || has_flag(&args, "--verbose");
    let proof_path = arg_value(&args, "-p");
    let sigs_path = arg_value(&args, "-s");

    if proof_path.is_none() && sigs_path.is_none() {
        eprintln!("Error: provide either -p <proof.bin> or -s <signatures.json>");
        return ExitCode::FAILURE;
    }
    if proof_path.is_some() && sigs_path.is_some() {
        eprintln!("Error: provide either -p or -s, not both");
        return ExitCode::FAILURE;
    }

    let pubkeys_path = match arg_value(&args, "-k") {
        Some(p) => p,
        None => { eprintln!("Error: missing -k <pubkeys.json>"); return ExitCode::FAILURE; }
    };
    let messages_path = match arg_value(&args, "-m") {
        Some(p) => p,
        None => { eprintln!("Error: missing -m <messages.json>"); return ExitCode::FAILURE; }
    };

    let pubkeys_json: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&pubkeys_path).unwrap()).unwrap();
    let messages: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&messages_path).unwrap()).unwrap();

    if messages.len() != pubkeys_json.len() {
        eprintln!("Error: {} messages but {} public keys", messages.len(), pubkeys_json.len());
        return ExitCode::FAILURE;
    }

    let mut msg_bytes: Vec<Vec<u8>> = Vec::new();
    let mut public_keys: Vec<PublicKey> = Vec::new();
    for (i, msg) in messages.iter().enumerate() {
        msg_bytes.push(msg.as_bytes().to_vec());
        let pk_hex = pubkeys_json[i]["public_key"].as_str().unwrap();
        let pk: [u8; 32] = hex::decode(pk_hex).unwrap().try_into().unwrap();
        public_keys.push(PublicKey { bytes: pk });
    }

    if let Some(sigs_path) = sigs_path {
        verify_signatures(&sigs_path, &msg_bytes, &public_keys, verbose)
    } else {
        verify_proof(&proof_path.unwrap(), &msg_bytes, &public_keys, verbose)
    }
}

fn verify_signatures(
    sigs_path: &str,
    messages: &[Vec<u8>],
    public_keys: &[PublicKey],
    verbose: bool,
) -> ExitCode {
    let sig_hexes: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(sigs_path).unwrap()).unwrap();

    if sig_hexes.len() != messages.len() {
        eprintln!("Error: {} signatures but {} messages", sig_hexes.len(), messages.len());
        return ExitCode::FAILURE;
    }

    let verify_start = Instant::now();

    for (i, sig_hex) in sig_hexes.iter().enumerate() {
        let sig_raw: Vec<u8> = hex::decode(sig_hex).unwrap();
        let mut sig = slh_dsa::Signature { bytes: [0u8; 7856] };
        sig.bytes.copy_from_slice(&sig_raw);

        if !slh_dsa::verify(&public_keys[i], &messages[i], &sig) {
            eprintln!("FAIL: signature {} invalid", i + 1);
            return ExitCode::FAILURE;
        }

        if verbose {
            eprintln!("  Signature {} valid", i + 1);
        }
    }

    let verify_time = verify_start.elapsed();

    println!("PASS");

    if verbose {
        println!("  Mode:        direct signature verification");
        println!("  Signatures:  {}", messages.len());
        println!("  Verify time: {}", fmt_duration(verify_time));
    }

    ExitCode::SUCCESS
}

fn verify_proof(
    proof_path: &str,
    messages: &[Vec<u8>],
    public_keys: &[PublicKey],
    verbose: bool,
) -> ExitCode {
    use methods::VERIFY_SIGNATURES_ID;
    use risc0_zkvm::Receipt;

    let receipt_bytes = std::fs::read(proof_path).unwrap();
    let receipt: Receipt = match bincode::deserialize(&receipt_bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL: cannot deserialize proof: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let verify_start = Instant::now();
    if let Err(e) = receipt.verify(VERIFY_SIGNATURES_ID) {
        eprintln!("FAIL: STARK proof invalid: {}", e);
        return ExitCode::FAILURE;
    }
    let verify_time = verify_start.elapsed();

    let (journal_n, journal_msgs, journal_pks): (u32, Vec<Vec<u8>>, Vec<PublicKey>) =
        match receipt.journal.decode() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("FAIL: cannot decode journal: {}", e);
                return ExitCode::FAILURE;
            }
        };

    if journal_n as usize != messages.len() {
        eprintln!("FAIL: proof covers {} signatures, expected {}", journal_n, messages.len());
        return ExitCode::FAILURE;
    }

    for i in 0..messages.len() {
        if journal_msgs[i] != messages[i] {
            eprintln!("FAIL: message {} does not match", i + 1);
            return ExitCode::FAILURE;
        }
        if journal_pks[i].bytes != public_keys[i].bytes {
            eprintln!("FAIL: public key {} does not match", i + 1);
            return ExitCode::FAILURE;
        }
    }

    println!("PASS");

    if verbose {
        println!("  Mode:        STARK proof verification");
        println!("  Signatures:  {}", journal_n);
        println!("  Proof size:  {} bytes ({:.1} KiB)", receipt_bytes.len(), receipt_bytes.len() as f64 / 1024.0);
        println!("  Verify time: {}", fmt_duration(verify_time));
    }

    ExitCode::SUCCESS
}
