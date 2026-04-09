/// Generate SLH-DSA-SHA2-128s keypairs.
///
/// Usage: keygen -n <count> -o <secrets.json> -p <pubkeys.json> [-v]

use cli::util::{arg_value, has_flag, rel_path};
use slh_dsa::{keygen, params::N};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "-h") || has_flag(&args, "--help") {
        eprintln!("Usage: keygen -n <count> -o <secrets.json> -p <pubkeys.json> [-v]");
        return ExitCode::SUCCESS;
    }

    let verbose = has_flag(&args, "-v") || has_flag(&args, "--verbose");

    let count: usize = match arg_value(&args, "-n").and_then(|s| s.parse().ok()) {
        Some(n) => n,
        None => {
            eprintln!("Usage: keygen -n <count> -o <secrets.json> -p <pubkeys.json> [-v]");
            return ExitCode::FAILURE;
        }
    };
    let secrets_path = match arg_value(&args, "-o") {
        Some(p) => p,
        None => { eprintln!("Error: missing -o <secrets.json>"); return ExitCode::FAILURE; }
    };
    let pubkeys_path = match arg_value(&args, "-p") {
        Some(p) => p,
        None => { eprintln!("Error: missing -p <pubkeys.json>"); return ExitCode::FAILURE; }
    };

    let mut secrets = Vec::with_capacity(count);
    let mut pubkeys = Vec::with_capacity(count);

    for i in 0..count {
        let mut seed = [0u8; 3 * N];
        let i_bytes = (i as u32).to_be_bytes();
        seed[0..4].copy_from_slice(&i_bytes);
        for j in 4..seed.len() {
            seed[j] = (i as u8).wrapping_add(j as u8);
        }

        let (pk, sk) = keygen(&seed);

        secrets.push(serde_json::json!({
            "public_key": hex::encode(&pk.bytes),
            "secret_key": hex::encode(&sk.bytes),
        }));
        pubkeys.push(serde_json::json!({
            "public_key": hex::encode(&pk.bytes),
        }));
    }

    std::fs::write(&secrets_path, serde_json::to_string_pretty(&secrets).unwrap()).unwrap();
    std::fs::write(&pubkeys_path, serde_json::to_string_pretty(&pubkeys).unwrap()).unwrap();

    if verbose {
        eprintln!("Generated {} keypair(s)", count);
        eprintln!("  Secrets:     {}", rel_path(&secrets_path));
        eprintln!("  Public keys: {}", rel_path(&pubkeys_path));
    }

    ExitCode::SUCCESS
}
