/// Sign messages with SLH-DSA-SHA2-128s keys.
///
/// Usage: sign -k <secrets.json> -m <messages.json> -o <signatures.json> [-v]

use cli::util::{arg_value, has_flag, rel_path};
use slh_dsa::{sign, SecretKey};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "-h") || has_flag(&args, "--help") {
        eprintln!("Usage: sign -k <secrets.json> -m <messages.json> -o <signatures.json> [-v]");
        return ExitCode::SUCCESS;
    }

    let verbose = has_flag(&args, "-v") || has_flag(&args, "--verbose");

    let secrets_path = match arg_value(&args, "-k") {
        Some(p) => p,
        None => {
            eprintln!("Usage: sign -k <secrets.json> -m <messages.json> -o <signatures.json> [-v]");
            return ExitCode::FAILURE;
        }
    };
    let messages_path = match arg_value(&args, "-m") {
        Some(p) => p,
        None => { eprintln!("Error: missing -m <messages.json>"); return ExitCode::FAILURE; }
    };
    let output_path = match arg_value(&args, "-o") {
        Some(p) => p,
        None => { eprintln!("Error: missing -o <signatures.json>"); return ExitCode::FAILURE; }
    };

    let secrets: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&secrets_path).unwrap()).unwrap();
    let messages: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&messages_path).unwrap()).unwrap();

    if messages.len() > secrets.len() {
        eprintln!("Error: {} messages but only {} keys", messages.len(), secrets.len());
        return ExitCode::FAILURE;
    }

    let mut sigs = Vec::with_capacity(messages.len());

    for (i, msg) in messages.iter().enumerate() {
        let sk_hex = secrets[i]["secret_key"].as_str().unwrap();
        let sk_bytes: Vec<u8> = hex::decode(sk_hex).unwrap();
        let sk = SecretKey {
            bytes: sk_bytes.try_into().unwrap(),
        };

        let sig = sign(&sk, msg.as_bytes());
        sigs.push(hex::encode(&sig.bytes));

        if verbose {
            eprintln!("Signed message {}: {:?}", i + 1, msg);
        }
    }

    std::fs::write(&output_path, serde_json::to_string_pretty(&sigs).unwrap()).unwrap();

    if verbose {
        eprintln!("Signed {} message(s)", sigs.len());
        eprintln!("  Signatures: {}", rel_path(&output_path));
    }

    ExitCode::SUCCESS
}
