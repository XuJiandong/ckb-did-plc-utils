#![allow(dead_code)]
#![allow(unused_imports)]
use ckb_did_plc_utils::{
    base32::{self, Alphabet},
    base64::{
        self,
        engine::{Engine, general_purpose::URL_SAFE_NO_PAD},
    },
    cbor4ii::core::{
        Value,
        dec::Decode,
        enc::Encode,
        utils::{BufWriter, SliceReader},
    },
    error::Error,
    operation::{
        Operation, parse_local_id, validate_2_operations, validate_genesis_operation,
        validate_operation_history,
    },
    pubkey::decode_base58btc,
    reader::validate_cbor_format,
};
use molecule::lazy_reader::{Cursor, Error as MoleculeError, Read};
use std::{boxed::Box, fs::read, vec::Vec};

fn test_one_vector(prev_file: &str, cur_file: &str, rotation_key_index: usize) {
    let prev_path = get_test_vector_path(prev_file);
    let cur_path = get_test_vector_path(cur_file);
    let prev_buf = read(&prev_path).unwrap_or_else(|_| panic!("Failed to read {}", prev_path));
    let cur_buf = read(&cur_path).unwrap_or_else(|_| panic!("Failed to read {}", cur_path));
    let result = validate_2_operations(&prev_buf, &cur_buf, rotation_key_index);
    assert!(result.is_ok());
}

fn load_did(name: &str) -> String {
    let path = format!("{}.did", name);
    let full_path = get_test_vector_path(&path);
    let did = read(&full_path).unwrap_or_else(|_| panic!("Failed to read {}", full_path));
    String::from_utf8(did).unwrap_or_else(|_| panic!("Failed to parse DID from {}", full_path))
}

fn get_test_vector_path(filename: &str) -> String {
    format!("../tools/gen-test-vectors/test-vectors/{}", filename)
}

fn parse_did(did: &str) -> Vec<u8> {
    let b32 = did.split("did:plc:").nth(1).unwrap();
    base32::decode(Alphabet::Rfc4648Lower { padding: false }, b32).unwrap()
}

#[test]
fn test_vectors_1_2() {
    test_one_vector("1-did-creation.cbor", "2-update-handle.cbor", 0);
}

#[test]
fn test_vectors_2_3() {
    test_one_vector("2-update-handle.cbor", "3-update-pds.cbor", 0);
}

#[test]
fn test_vectors_3_4() {
    test_one_vector("3-update-pds.cbor", "4-update-atproto-key.cbor", 0);
}

#[test]
fn test_vectors_4_5() {
    test_one_vector(
        "4-update-atproto-key.cbor",
        "5-update-rotation-keys.cbor",
        0,
    );
}

#[test]
fn test_vectors_5_6() {
    test_one_vector("5-update-rotation-keys.cbor", "6-update-handle.cbor", 1);
}

#[test]
fn test_vectors_6_7() {
    // tombstone is not allowed
    let prev_path = get_test_vector_path("6-update-handle.cbor");
    let cur_path = get_test_vector_path("7-tombstone.cbor");
    let prev_buf = read(&prev_path).unwrap_or_else(|_| panic!("Failed to read {}", prev_path));
    let cur_buf = read(&cur_path).unwrap_or_else(|_| panic!("Failed to read {}", cur_path));
    let result = validate_2_operations(&prev_buf, &cur_buf, 0);
    assert!(result.is_err());
}
#[test]
fn test_vector_legacy_1_2() {
    test_one_vector(
        "1-did-creation-legacy.cbor",
        "2-update-rotation-keys-legacy.cbor",
        1,
    );
}

#[test]
fn test_genesis_operation() {
    let genesis_path = get_test_vector_path("1-did-creation.cbor");
    let genesis_buf =
        read(&genesis_path).unwrap_or_else(|_| panic!("Failed to read {}", genesis_path));
    let did = load_did("creation");
    let result = validate_genesis_operation(&genesis_buf, &parse_did(&did), 0);
    assert!(result.is_ok());
}

#[test]
fn test_genesis_operation_wrong_did() {
    let genesis_path = get_test_vector_path("1-did-creation.cbor");
    let genesis_buf = read(&genesis_path).expect(&format!("Failed to read {}", genesis_path));
    let result = validate_genesis_operation(&genesis_buf, &vec![0; 15], 0);
    assert!(matches!(result, Err(Error::DidMismatched)));
}

#[test]
fn test_legacy_genesis_operation() {
    let genesis_path = get_test_vector_path("1-did-creation-legacy.cbor");
    let genesis_buf =
        read(&genesis_path).unwrap_or_else(|_| panic!("Failed to read {}", genesis_path));
    let did = load_did("creation-legacy");
    let result = validate_genesis_operation(&genesis_buf, &parse_did(&did), 0);
    assert!(result.is_ok());
}

fn remove_operation_services(buf: &[u8]) -> Vec<u8> {
    let mut reader = SliceReader::new(buf);
    let raw = Value::decode(&mut reader).unwrap();
    let update_raw = match raw {
        Value::Map(map) => {
            let new_map = map
                .into_iter()
                .map(|(key, value)| {
                    if key == Value::Text("services".to_string()) {
                        (key, Value::Map(vec![]))
                    } else {
                        (key, value)
                    }
                })
                .collect();
            Value::Map(new_map)
        }
        _ => raw,
    };
    let mut writer = BufWriter::new(Vec::new());
    update_raw.encode(&mut writer).unwrap();
    writer.into_inner()
}

fn remove_operation_type(buf: &[u8]) -> Vec<u8> {
    let mut reader = SliceReader::new(buf);
    let raw = Value::decode(&mut reader).unwrap();
    let update_raw = match raw {
        Value::Map(map) => {
            let new_map = map
                .into_iter()
                .map(|(key, value)| {
                    if key == Value::Text("type".to_string()) {
                        // remove the type field
                        (key, Value::Null)
                    } else {
                        (key, value)
                    }
                })
                .collect();
            Value::Map(new_map)
        }
        _ => raw,
    };
    let mut writer = BufWriter::new(Vec::new());
    update_raw.encode(&mut writer).unwrap();
    writer.into_inner()
}

fn modify_operation_sig(buf: &[u8]) -> Vec<u8> {
    let mut reader = SliceReader::new(buf);
    let raw = Value::decode(&mut reader).unwrap();
    let update_raw = match raw {
        Value::Map(map) => {
            let new_map = map
                .into_iter()
                .map(|(key, value)| {
                    if key == Value::Text("sig".to_string()) {
                        match value {
                            Value::Text(sig) => {
                                let engine = URL_SAFE_NO_PAD;
                                let sig = engine.decode(sig).unwrap();
                                let mut sig = sig.clone();
                                sig[0] ^= 1;
                                let sig = engine.encode(sig);
                                (key, Value::Text(sig))
                            }
                            _ => (key, value),
                        }
                    } else {
                        (key, value)
                    }
                })
                .collect();
            Value::Map(new_map)
        }
        _ => raw,
    };
    let mut writer = BufWriter::new(Vec::new());
    update_raw.encode(&mut writer).unwrap();
    writer.into_inner()
}

#[test]
fn test_vectors_1_2_wrong_sig() {
    let prev_path = get_test_vector_path("1-did-creation.cbor");
    let cur_path = get_test_vector_path("2-update-handle.cbor");
    let prev_buf = read(&prev_path).unwrap_or_else(|_| panic!("Failed to read {}", prev_path));
    let cur_buf = read(&cur_path).unwrap_or_else(|_| panic!("Failed to read {}", cur_path));

    let cur_buf = modify_operation_sig(&cur_buf);

    let result = validate_2_operations(&prev_buf, &cur_buf, 0);
    assert!(result.is_err());
}
#[test]
fn test_vectors_1_2_wrong_cid() {
    let prev_path = get_test_vector_path("1-did-creation.cbor");
    let cur_path = get_test_vector_path("2-update-handle.cbor");
    let prev_buf = read(&prev_path).unwrap_or_else(|_| panic!("Failed to read {}", prev_path));
    let cur_buf = read(&cur_path).unwrap_or_else(|_| panic!("Failed to read {}", cur_path));

    // update previous operation's signature(part of content) to make CID changed
    let prev_buf = modify_operation_sig(&prev_buf);

    let result = validate_2_operations(&prev_buf, &cur_buf, 0);
    assert!(matches!(result, Err(Error::InvalidPrev)));
}

#[test]
fn test_vector_1_2_wrong_operation_type() {
    let prev_path = get_test_vector_path("1-did-creation.cbor");
    let cur_path = get_test_vector_path("2-update-handle.cbor");
    let prev_buf = read(&prev_path).unwrap_or_else(|_| panic!("Failed to read {}", prev_path));
    let cur_buf = read(&cur_path).unwrap_or_else(|_| panic!("Failed to read {}", cur_path));

    let prev_buf = remove_operation_type(&prev_buf);

    let result = validate_2_operations(&prev_buf, &cur_buf, 0);
    assert!(matches!(result, Err(Error::InvalidOperation)));
}

#[test]
fn test_vector_1_2_wrong_operation_content() {
    let prev_path = get_test_vector_path("1-did-creation.cbor");
    let cur_path = get_test_vector_path("2-update-handle.cbor");
    let prev_buf = read(&prev_path).unwrap_or_else(|_| panic!("Failed to read {}", prev_path));
    let cur_buf = read(&cur_path).unwrap_or_else(|_| panic!("Failed to read {}", cur_path));

    // remove operation service to make content changed, it causes the signature validation failed.
    let cur_buf = remove_operation_services(&cur_buf);

    let result = validate_2_operations(&prev_buf, &cur_buf, 0);
    assert!(matches!(result, Err(Error::VerifySignatureFailed)));
}
#[test]
fn test_not_genesis_operation() {
    // Only true genesis operations (with prev as null) can pass validation
    let non_genesis_path = get_test_vector_path("2-update-handle.cbor"); // This is an update operation with prev
    let buf = read(&non_genesis_path).expect("Failed to read file");
    let binary_did = vec![0u8; 15]; // Arbitrary DID, should match in practice
    let result = validate_genesis_operation(&buf, &binary_did, 0);
    assert!(matches!(result, Err(Error::NotGenesisOperation)));
}
struct MockReader {
    total_size: usize,
    data: Vec<u8>,
}

impl Read for MockReader {
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, MoleculeError> {
        if offset >= self.total_size {
            return Err(MoleculeError::OutOfBound(offset, self.total_size));
        }
        let len = std::cmp::min(buf.len(), self.total_size - offset);
        buf[..len].copy_from_slice(&self.data[offset..offset + len]);
        Ok(len)
    }
}

#[test]
fn test_molecule_error_invalid_offset() {
    let reader = MockReader {
        total_size: 10,
        data: vec![0u8; 10],
    };
    let mut buf = [0u8; 5];
    let result = reader.read(&mut buf, 15);
    assert!(matches!(result, Err(MoleculeError::OutOfBound(_, _))));
    let wrapped_error = Error::from(result.unwrap_err());
    println!("{:?}", wrapped_error);
    assert!(matches!(
        wrapped_error,
        Error::MoleculeError(MoleculeError::OutOfBound(_, _))
    ));
}

#[test]
fn test_molecule_error_empty_buffer() {
    // Empty buffer
    let reader = MockReader {
        total_size: 0,
        data: vec![],
    };
    let mut buf = [0u8; 1];
    let result = reader.read(&mut buf, 0);
    assert!(matches!(result, Err(MoleculeError::OutOfBound(_, _))));
}

#[test]
fn test_utils_error_invalid_history() {
    // Step 1: Create empty history to trigger InvalidHistory
    let binary_did = vec![0u8; 15];
    let history: Vec<Cursor> = vec![];
    let rotation_key_indices: Vec<usize> = vec![];
    let msg = vec![];
    let final_sig = vec![];

    let result =
        validate_operation_history(&binary_did, history, rotation_key_indices, &msg, &final_sig);

    // Step 2: Verify returns UtilsError::InvalidHistory
    assert!(matches!(result, Err(Error::InvalidHistory)));

    // Additional test: History length does not match indices
    let history = vec![Cursor::new(
        0,
        Box::new(MockReader {
            total_size: 0,
            data: vec![],
        }),
    )];
    let rotation_key_indices = vec![0]; // Length should be history.len() + 1 = 2
    let result2 =
        validate_operation_history(&binary_did, history, rotation_key_indices, &msg, &final_sig);
    assert!(matches!(result2, Err(Error::InvalidHistory)));
}

#[test]
fn test_utils_error_invalid_cbor() {
    // Create an invalid CBOR data Cursor
    let invalid_cbor_data: Vec<u8> = vec![0x82]; // Invalid CBOR: Expects an array of 2 elements but has no content
    let total_size = invalid_cbor_data.len();
    let cursor = Cursor::new(
        total_size,
        Box::new(MockReader {
            total_size,
            data: invalid_cbor_data,
        }),
    );

    let result = validate_cbor_format(cursor);

    assert!(matches!(result, Err(Error::InvalidCbor)));
}

#[test]
fn test_utils_error_invalid_did_format() {
    // Test invalid prefix
    let invalid_did = b"did:invalid:abc123";
    let result = parse_local_id(invalid_did);
    assert!(matches!(result, Err(Error::InvalidDidFormat)));

    // Test invalid base32 encoding
    let invalid_base32 = b"did:plc:invalid_base32";
    let result2 = parse_local_id(invalid_base32);
    assert!(matches!(result2, Err(Error::InvalidDidFormat)));
}

#[test]
fn test_utils_error_tombstone_in_history() {
    let did = load_did("creation");
    let binary_did = parse_did(&did);

    let files = vec![
        "1-did-creation.cbor",
        "2-update-handle.cbor",
        "3-update-pds.cbor",
        "4-update-atproto-key.cbor",
        "5-update-rotation-keys.cbor",
        "6-update-handle.cbor",
        "7-tombstone.cbor",
    ];

    let mut history: Vec<Cursor> = vec![];
    for file in files {
        let path = get_test_vector_path(file);
        let buf = read(&path).unwrap_or_else(|_| panic!("Failed to read {}", path));
        let total_size = buf.len();
        history.push(Cursor::new(
            total_size,
            Box::new(MockReader {
                total_size,
                data: buf,
            }),
        ));
    }
    let rotation_key_indices: Vec<usize> = vec![0, 0, 0, 0, 0, 1, 0, 0];
    let msg = vec![0u8; 32];
    let final_sig = vec![0u8; 65];

    let result =
        validate_operation_history(&binary_did, history, rotation_key_indices, &msg, &final_sig);

    assert!(result.is_err());
}

pub fn set_rotation_keys_to_string(buf: &[u8]) -> Vec<u8> {
    let mut reader = SliceReader::new(buf);
    let raw = Value::decode(&mut reader).unwrap();

    // rotationKeys: Array(...)  ->  "not-an-array"
    let updated = match raw {
        Value::Map(map) => {
            let new_map = map
                .into_iter()
                .map(|(key, value)| {
                    if key == Value::Text("rotationKeys".to_string()) {
                        (key, Value::Text("not-an-array".to_string()))
                    } else {
                        (key, value)
                    }
                })
                .collect();
            Value::Map(new_map)
        }
        _ => raw,
    };

    let mut writer = BufWriter::new(Vec::new());
    updated.encode(&mut writer).unwrap();
    writer.into_inner()
}

pub fn set_prev_field(buf: &[u8], new_prev: &str) -> Vec<u8> {
    let mut reader = SliceReader::new(buf);
    let raw = Value::decode(&mut reader).unwrap();

    // prev: <old>  ->  prev: <new_prev>
    let updated = match raw {
        Value::Map(map) => {
            let new_map = map
                .into_iter()
                .map(|(key, value)| {
                    if key == Value::Text("prev".to_string()) {
                        (key, Value::Text(new_prev.to_string()))
                    } else {
                        (key, value)
                    }
                })
                .collect();
            Value::Map(new_map)
        }
        _ => raw,
    };

    let mut writer = BufWriter::new(Vec::new());
    updated.encode(&mut writer).unwrap();
    writer.into_inner()
}

pub fn replace_first_rotation_key(buf: &[u8], new_key: &str) -> Vec<u8> {
    let mut reader = SliceReader::new(buf);
    let raw = Value::decode(&mut reader).unwrap();

    let updated = match raw {
        Value::Map(map) => {
            let new_map = map
                .into_iter()
                .map(|(k, v)| {
                    if k == Value::Text("rotationKeys".to_string()) {
                        if let Value::Array(mut arr) = v {
                            if !arr.is_empty() {
                                arr[0] = Value::Text(new_key.to_string());
                            }
                            (k, Value::Array(arr))
                        } else {
                            (k, v)
                        }
                    } else {
                        (k, v)
                    }
                })
                .collect();
            Value::Map(new_map)
        }
        _ => raw,
    };

    let mut w = BufWriter::new(Vec::new());
    updated.encode(&mut w).unwrap();
    w.into_inner()
}

fn did_key_from_bytes(bytes: &[u8]) -> String {
    let encoded = multibase::encode(multibase::Base::Base58Btc, bytes);
    format!("did:key:{}", encoded)
}

#[test]
fn test_rotation_keys_decode_error() {
    let prev = read(get_test_vector_path("1-did-creation.cbor")).unwrap();
    let cur = read(get_test_vector_path("2-update-handle.cbor")).unwrap();

    let prev_bad = set_rotation_keys_to_string(&prev);
    let new_cid = {
        let op = Operation::from_slice(&prev_bad).expect("decode prev_bad");
        op.generate_cid().expect("cid")
    };
    let cur_patched = set_prev_field(&cur, &new_cid);
    let res = validate_2_operations(&prev_bad, &cur_patched, 0);
    assert!(matches!(res, Err(Error::RotationKeysDecodeError)));
}

#[test]
fn test_invalid_key() {
    let prev = read(get_test_vector_path("1-did-creation.cbor")).unwrap();
    let cur = read(get_test_vector_path("2-update-handle.cbor")).unwrap();

    {
        let prev_bad = set_rotation_keys_to_string(&prev);
        let res = validate_2_operations(&prev_bad, &cur, 0);
        eprintln!("[case0] expect InvalidPrev -> got: {res:?}");
        assert!(matches!(res, Err(Error::InvalidPrev)));
    }

    // Helper to run a case that expects InvalidKey:
    let run_invalid_key_case = |label: &str, prev_bad: Vec<u8>| {
        // Recompute CID for modified prev
        let new_cid = Operation::from_slice(&prev_bad)
            .unwrap()
            .generate_cid()
            .unwrap();
        // Patch cur.prev to pass the chain check
        let cur_patched = set_prev_field(&cur, &new_cid);
        // Now the pipeline can reach key parsing / verification parts
        let res = validate_2_operations(&prev_bad, &cur_patched, 0);
        eprintln!("[{label}] expect InvalidKey -> got: {res:?}");
        assert!(matches!(res, Err(Error::InvalidKey)));
    };

    {
        let bad_key = "did:key:ffooo"; // bad multibase prefix
        let prev_bad = replace_first_rotation_key(&prev, bad_key);
        run_invalid_key_case("case1_not_base58btc_prefix", prev_bad);
    }

    {
        let bad_key = "did:pkh:zabc"; // wrong DID method
        let prev_bad = replace_first_rotation_key(&prev, bad_key);
        run_invalid_key_case("case2_not_did_key_prefix", prev_bad);
    }

    {
        let mut raw = vec![0x00, 0x00]; // invalid multicodec tag
        raw.extend(std::iter::repeat(0x42).take(33)); // 33 bytes payload just to pass len check
        let bad_key = did_key_from_bytes(&raw);
        let prev_bad = replace_first_rotation_key(&prev, &bad_key);
        run_invalid_key_case("case3_wrong_multicodec_tag", prev_bad);
    }

    {
        let mut raw = vec![0xE7, 0x01]; // secp256k1 tag
        raw.extend([0x03; 32]); // only 32 bytes, should be 33
        let bad_key = did_key_from_bytes(&raw);
        let prev_bad = replace_first_rotation_key(&prev, &bad_key);
        run_invalid_key_case("case4_wrong_length", prev_bad);
    }

    // {
    //     let mut raw = vec![0xE7, 0x01]; // secp256k1 tag
    //     raw.push(0x02); // compressed prefix
    //     raw.extend([0u8; 32]); // invalid X (all zeros) -> invalid curve point
    //     let bad_key = did_key_from_bytes(&raw);
    //     let prev_bad = replace_first_rotation_key(&prev, &bad_key);
    //     run_invalid_key_case("case5_not_on_curve_verify_stage", prev_bad);
    // }

    {
        // Case6: Valid key round-trip via did_key_from_bytes (control case)
        // 1) extract original did:key
        let mut reader = SliceReader::new(&prev);
        let root = Value::decode(&mut reader).unwrap();
        let mut orig_key = String::new();
        if let Value::Map(map) = root {
            for (k, v) in map {
                if k == Value::Text("rotationKeys".to_string()) {
                    if let Value::Array(arr) = v {
                        if let Value::Text(s) = &arr[0] {
                            orig_key = s.clone();
                        }
                    }
                }
            }
        }
        assert!(
            orig_key.starts_with("did:key:"),
            "[case6_valid_key] invalid format"
        );

        // 2) decode base58btc correctly (NO extra 'z')
        let zpart = &orig_key[8..]; // "z...."
        let raw_bytes = decode_base58btc(zpart).expect("decode_base58btc");

        assert_eq!(raw_bytes.len(), 35, "[case6_valid_key] unexpected length");
        assert!(
            (raw_bytes[0] == 0xE7 && raw_bytes[1] == 0x01) || // secp256k1
                (raw_bytes[0] == 0x80 && raw_bytes[1] == 0x24), // secp256r1
            "[case6_valid_key] unexpected multicodec tag: {:02x} {:02x}",
            raw_bytes[0],
            raw_bytes[1]
        );

        // 3) round-trip encode and compare
        let roundtrip_key = did_key_from_bytes(&raw_bytes);
        assert_eq!(
            roundtrip_key, orig_key,
            "[case6_valid_key] round-trip mismatch: {roundtrip_key} != {orig_key}"
        );

        // 4) replace + patch + validate should be Ok(())
        let prev_good = replace_first_rotation_key(&prev, &roundtrip_key);
        let new_cid = Operation::from_slice(&prev_good)
            .unwrap()
            .generate_cid()
            .unwrap();
        let cur_patched = set_prev_field(&cur, &new_cid);

        let res = validate_2_operations(&prev_good, &cur_patched, 0);
        eprintln!("[case6_valid_key_roundtrip] expect Ok(()) -> got: {res:?}");
        assert!(res.is_ok());
    }
}

#[test]
fn test_invalid_key_index() {
    let prev = read(get_test_vector_path("1-did-creation.cbor")).unwrap();
    let cur = read(get_test_vector_path("2-update-handle.cbor")).unwrap();

    let res = validate_2_operations(&prev, &cur, 99);
    assert!(matches!(res, Err(Error::InvalidKeyIndex)));
}

#[test]
fn test_invalid_signature() {
    use ckb_did_plc_utils::{
        cbor4ii::core::{
            Value,
            dec::Decode,
            enc::Encode,
            utils::{BufWriter, SliceReader},
        },
        error::Error,
        operation::validate_2_operations,
    };
    use std::fs::read;

    let prev = read(get_test_vector_path("1-did-creation.cbor")).unwrap();
    let cur = read(get_test_vector_path("2-update-handle.cbor")).unwrap();

    // helper: set top-level "sig" as Text to a specific string
    let set_sig_text = |buf: &[u8], s: &str| {
        let mut r = SliceReader::new(buf);
        let mut root = Value::decode(&mut r).unwrap();
        if let Value::Map(ref mut pairs) = root {
            for (k, v) in pairs.iter_mut() {
                if *k == Value::Text("sig".into()) {
                    *v = Value::Text(s.to_string());
                }
            }
        }
        let mut w = BufWriter::new(Vec::new());
        root.encode(&mut w).unwrap();
        w.into_inner()
    };

    // -------- Case 1: non-base64url characters ('!' and '*') -> base64url decode fails -> InvalidSignature
    {
        let cur_bad = set_sig_text(&cur, "not-base64url!!**");
        let res = validate_2_operations(&prev, &cur_bad, 0);
        eprintln!("[Case 1] expect InvalidSignature -> got: {res:?}");
        assert!(matches!(res, Err(Error::InvalidSignature)));
    }

    // -------- Case 2: valid-looking length but still not base64url (e.g., has a space) -> InvalidSignature
    {
        let cur_bad = set_sig_text(&cur, "abcd efgh"); // space is invalid for base64url
        let res = validate_2_operations(&prev, &cur_bad, 0);
        eprintln!("[Case 2] expect InvalidSignature -> got: {res:?}");
        assert!(matches!(res, Err(Error::InvalidSignature)));
    }
}

#[test]
fn test_invalid_signature_padding() {
    use ckb_did_plc_utils::cbor4ii::core::{
        Value,
        dec::Decode,
        enc::Encode,
        utils::{BufWriter, SliceReader},
    };
    use ckb_did_plc_utils::{error::Error, operation::validate_2_operations};
    use std::fs::read;

    let prev = read(get_test_vector_path("1-did-creation.cbor")).unwrap();
    let cur = read(get_test_vector_path("2-update-handle.cbor")).unwrap();

    // ---- read original sig text from `cur` (must be URL_SAFE_NO_PAD, meaning no '=') ----
    let orig_sig: String = 'find_sig: {
        let mut r = SliceReader::new(&cur);
        let root = Value::decode(&mut r).unwrap();
        if let Value::Map(map) = root {
            for (k, v) in map {
                if let Value::Text(k_str) = k {
                    if k_str == "sig" {
                        if let Value::Text(s) = v {
                            break 'find_sig s;
                        } else {
                            panic!("`sig` is not Text");
                        }
                    }
                }
            }
            panic!("`sig` field not found");
        } else {
            panic!("root is not a Map");
        }
    };
    assert!(!orig_sig.ends_with('='), "fixture sig already has padding?");

    // =============== Case 1: append a single '=' ===============
    {
        // make a new cur with sig = orig_sig + "="
        let cur_padded = {
            let mut r = SliceReader::new(&cur);
            let mut root = Value::decode(&mut r).unwrap();
            if let Value::Map(ref mut pairs) = root {
                for (k, v) in pairs.iter_mut() {
                    if *k == Value::Text("sig".into()) {
                        *v = Value::Text(format!("{orig_sig}="));
                    }
                }
            }
            let mut w = BufWriter::new(Vec::new());
            root.encode(&mut w).unwrap();
            w.into_inner()
        };

        let res = validate_2_operations(&prev, &cur_padded, 0);
        eprintln!("[Case 1: sig ends with '='] expect InvalidSignaturePadding -> got: {res:?}");
        assert!(matches!(res, Err(Error::InvalidSignaturePadding)));
    }

    // =============== Case 2: append '==' ===============
    {
        let cur_padded2 = {
            let mut r = SliceReader::new(&cur);
            let mut root = Value::decode(&mut r).unwrap();
            if let Value::Map(ref mut pairs) = root {
                for (k, v) in pairs.iter_mut() {
                    if *k == Value::Text("sig".into()) {
                        *v = Value::Text(format!("{orig_sig}=="));
                    }
                }
            }
            let mut w = BufWriter::new(Vec::new());
            root.encode(&mut w).unwrap();
            w.into_inner()
        };

        let res = validate_2_operations(&prev, &cur_padded2, 0);
        eprintln!("[Case 2: sig ends with '=='] expect InvalidSignaturePadding -> got: {res:?}");
        assert!(matches!(res, Err(Error::InvalidSignaturePadding)));
    }
}
