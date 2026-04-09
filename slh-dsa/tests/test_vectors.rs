/// Test vectors from NIST ACVP (SLH-DSA-keyGen-FIPS205)
/// Source: https://github.com/mjosaarinen/py-acvp-pqc/blob/main/json-copy/SLH-DSA-keyGen-FIPS205/

use slh_dsa::{keygen, params::N};

fn hex_to_bytes<const LEN: usize>(hex: &str) -> [u8; LEN] {
    let mut bytes = [0u8; LEN];
    for i in 0..LEN {
        bytes[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

/// ACVP keyGen test vector tcId: 1
#[test]
fn test_acvp_keygen_vector_1() {
    let sk_seed: [u8; N] = hex_to_bytes("AC379F047FAAB2004F3AE32350AC9A3D");
    let sk_prf: [u8; N] = hex_to_bytes("829FFF0AA59E956A87F3971C4D58E710");
    let pk_seed: [u8; N] = hex_to_bytes("0566D240CC519834322EAFBCC73C79F5");

    let mut seed = [0u8; 3 * N];
    seed[0..N].copy_from_slice(&sk_seed);
    seed[N..2 * N].copy_from_slice(&sk_prf);
    seed[2 * N..3 * N].copy_from_slice(&pk_seed);

    let (pk, sk) = keygen(&seed);

    let expected_pk: [u8; 32] =
        hex_to_bytes("0566D240CC519834322EAFBCC73C79F5A4B84F02E8BF0CBD54017B2D3C494B57");
    let expected_sk: [u8; 64] = hex_to_bytes(
        "AC379F047FAAB2004F3AE32350AC9A3D\
         829FFF0AA59E956A87F3971C4D58E710\
         0566D240CC519834322EAFBCC73C79F5\
         A4B84F02E8BF0CBD54017B2D3C494B57",
    );

    assert_eq!(pk.bytes, expected_pk, "public key mismatch");
    assert_eq!(sk.bytes, expected_sk, "secret key mismatch");
}

/// ACVP keyGen test vector tcId: 2
#[test]
fn test_acvp_keygen_vector_2() {
    let sk_seed: [u8; N] = hex_to_bytes("20D43B51FB11AF1FE3C6459B7BB90D50");
    let sk_prf: [u8; N] = hex_to_bytes("4F63BA1D6CC9B355D47E49C958658160");
    let pk_seed: [u8; N] = hex_to_bytes("F420447CFE8F1823CE5BBFF0030CC69D");

    let mut seed = [0u8; 3 * N];
    seed[0..N].copy_from_slice(&sk_seed);
    seed[N..2 * N].copy_from_slice(&sk_prf);
    seed[2 * N..3 * N].copy_from_slice(&pk_seed);

    let (pk, sk) = keygen(&seed);

    let expected_pk: [u8; 32] =
        hex_to_bytes("F420447CFE8F1823CE5BBFF0030CC69D31A2F32390C22B1AB974B5F5A2B3844E");
    let expected_sk: [u8; 64] = hex_to_bytes(
        "20D43B51FB11AF1FE3C6459B7BB90D50\
         4F63BA1D6CC9B355D47E49C958658160\
         F420447CFE8F1823CE5BBFF0030CC69D\
         31A2F32390C22B1AB974B5F5A2B3844E",
    );

    assert_eq!(pk.bytes, expected_pk, "public key mismatch");
    assert_eq!(sk.bytes, expected_sk, "secret key mismatch");
}

/// Verify base_2b correctly extracts b-bit values for both WOTS (b=4) and FORS (b=12).
#[test]
fn test_base_2b() {
    use slh_dsa::wots::base_2b;

    // b=4: each nibble extracted MSB-first
    let data = [0xAB, 0xCD];
    let digits: [u16; 4] = base_2b(&data, 4);
    assert_eq!(digits, [0xA, 0xB, 0xC, 0xD]);

    // b=8: each byte is one digit
    let digits: [u16; 2] = base_2b(&data, 8);
    assert_eq!(digits, [0xAB, 0xCD]);

    // b=12: 12-bit values from MSB
    // 24 bits: 0xABCDEF → first 12 bits: 0xABC, next 12 bits: 0xDEF
    let data12 = [0xAB, 0xCD, 0xEF];
    let digits: [u16; 2] = base_2b(&data12, 12);
    assert_eq!(digits, [0xABC, 0xDEF]);
}

/// Basic round-trip test: keygen → sign → verify
#[test]
fn test_sign_verify_roundtrip() {
    let mut seed = [0u8; 3 * N];
    for i in 0..seed.len() {
        seed[i] = i as u8;
    }

    let (pk, sk) = keygen(&seed);
    let msg = b"Hello, SLH-DSA-SHA2-128s!";
    let sig = slh_dsa::sign(&sk, msg);

    assert!(
        slh_dsa::verify(&pk, msg, &sig),
        "valid signature should verify"
    );
    assert!(
        !slh_dsa::verify(&pk, b"tampered", &sig),
        "tampered message should not verify"
    );
}
