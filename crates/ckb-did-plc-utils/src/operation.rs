// Implementation choices:
// 1. No serde used. It would make code bloat and is not necessary.
// 2. No CID crate used. The CID implementation would require multibase, multihash,
//    and multicodec support, which adds too many dependency crates.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use base32::Alphabet;
use cbor4ii::core::Value;
use cbor4ii::core::dec::Decode;
use cbor4ii::core::enc::Encode;
use cbor4ii::core::utils::{BufWriter, SliceReader};

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::pubkey::PublicKey;

// steps to verify 2 DID PLC operations:
// * deserialize previous operation
// * validate previous operation
// * deserialize current operation
// * validate current operation
// * generate cid from previous operation
// * verify cid is same in current operation
// * get all rotation keys from previous operation
// * create unsigned operation from current operation
// * verify signature in current operation with current unsigned operation and rotation keys

// exception in legacy operation:
// 1. "type" field is "create"
// 2. "signingKey" and "signingKey" are both used as rotation keys

pub struct Operation {
    raw: Value,
    cached_keys: Vec<String>,
}

impl Operation {
    pub fn from_slice(buf: &[u8]) -> Result<Self, Error> {
        let mut reader = SliceReader::new(buf);
        let raw = Value::decode(&mut reader).map_err(|_| Error::InvalidOperation)?;
        let mut op = Operation {
            raw,
            cached_keys: vec![],
        };
        op.update_cached_keys()?;
        Ok(op)
    }
    fn update_cached_keys(&mut self) -> Result<(), Error> {
        let mut cached_keys = vec![];
        match &self.raw {
            Value::Map(map) => {
                for (key, _) in map {
                    if let Value::Text(key) = key {
                        cached_keys.push(key.clone());
                    } else {
                        return Err(Error::InvalidOperation);
                    }
                }
            }
            _ => {
                return Err(Error::InvalidOperation);
            }
        }
        self.cached_keys = cached_keys;
        Ok(())
    }

    pub fn new_unsigned_operation(&self) -> Result<Self, Error> {
        let raw = self.raw.clone();
        let mut map = Vec::new();
        if let Value::Map(original_map) = &raw {
            for (key, value) in original_map {
                if let Value::Text(key_str) = key {
                    // Creates an unsigned operation by removing the "sig" field while preserving
                    // the original key/value pairs and their order. This unsigned operation will
                    // be used for signature verification.
                    if key_str != "sig" {
                        map.push((key.clone(), value.clone()));
                    }
                }
            }
        }
        let unsigned_raw = Value::Map(map);
        let mut op = Operation {
            raw: unsigned_raw,
            cached_keys: vec![],
        };
        op.update_cached_keys()?;
        Ok(op)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.is_legacy() {
            if self.has_keys(&[
                "type",
                "signingKey",
                "recoveryKey",
                "handle",
                "service",
                "prev",
                "sig",
            ]) {
                return Ok(());
            } else {
                return Err(Error::InvalidOperation);
            }
        } else if self.is_tombstone() {
            if self.has_keys(&["type", "prev", "sig"]) {
                return Ok(());
            } else {
                return Err(Error::InvalidOperation);
            }
        } else {
            if !self.is_operation() {
                return Err(Error::InvalidOperation);
            }
            if self.has_keys(&[
                "type",
                "rotationKeys",
                "verificationMethods",
                "alsoKnownAs",
                "services",
                "prev",
                "sig",
            ]) {
                return Ok(());
            } else {
                return Err(Error::InvalidOperation);
            }
        }
    }
    pub fn is_operation(&self) -> bool {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Text(value)) = (k, v) {
                    if key == "type" && value == "plc_operation" {
                        return true;
                    } else {
                        return false;
                    }
                }
            }
        }
        false
    }
    pub fn is_legacy(&self) -> bool {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Text(value)) = (k, v) {
                    if key == "type" && value == "create" {
                        return true;
                    }
                }
            }
        }
        false
    }
    pub fn is_tombstone(&self) -> bool {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Text(value)) = (k, v) {
                    if key == "type" && value == "plc_tombstone" {
                        return true;
                    }
                }
            }
        }
        false
    }
    fn get_rotation_keys(&self) -> Result<Vec<PublicKey>, Error> {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Array(value)) = (k, v) {
                    if key == "rotationKeys" {
                        let mut rotation_keys = vec![];
                        for item in value {
                            if let Value::Text(key) = item {
                                let key = PublicKey::from_str(key)?;
                                rotation_keys.push(key);
                            }
                        }
                        return Ok(rotation_keys);
                    }
                }
            }
        }
        Err(Error::RotationKeysDecodeError)
    }

    pub fn get_signature(&self) -> Result<Vec<u8>, Error> {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Text(value)) = (k, v) {
                    if key == "sig" {
                        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                        let decoded_sig =
                            engine.decode(value).map_err(|_| Error::InvalidSignature)?;
                        return Ok(decoded_sig);
                    }
                }
            }
        }
        Err(Error::InvalidOperation)
    }
    // note, the `pubkeys`` are from previous operation
    fn verify_signature(&self, pubkeys: &Vec<PublicKey>) -> Result<(), Error> {
        // TODO:
        Ok(())
    }
    pub fn get_cid(&self) -> Result<String, Error> {
        let mut writer = BufWriter::new(Vec::new());
        self.raw
            .encode(&mut writer)
            .map_err(|_| Error::InvalidOperation)?;
        let dag = writer.into_inner();
        let hashed = Sha256::digest(dag.as_slice());

        // the following algorithm is to assemble CID manually:
        // CIDv1
        // base32 multibase encoding (prefix: b)
        // dag-cbor multibase type (code: 0x71)
        // sha-256 multihash (code: 0x12)
        let mut raw_cid = vec![0x01, 0x71, 0x12, 0x20];
        raw_cid.extend_from_slice(hashed.as_slice());

        let b32 = base32::encode(
            Alphabet::Rfc4648Lower { padding: false },
            raw_cid.as_slice(),
        );
        Ok("b".to_owned() + &b32)
    }
    pub fn get_did(&self) -> Result<String, Error> {
        let mut writer = BufWriter::new(Vec::new());
        self.raw
            .encode(&mut writer)
            .map_err(|_| Error::InvalidOperation)?;
        let dag = writer.into_inner();
        let hashed = Sha256::digest(dag.as_slice());
        let b32 = base32::encode(Alphabet::Rfc4648Lower { padding: false }, hashed.as_slice());
        // The identifier part is 24 characters long, including only characters from the base32 encoding set.
        Ok(format!("did:plc:{}", &b32[0..24]))
    }
    fn has_keys(&self, keys: &[&str]) -> bool {
        keys.iter()
            .all(|&key| self.cached_keys.iter().any(|k| k == key))
    }
}

pub fn validate_2_operations(prev_buf: &[u8], cur_buf: &[u8]) -> Result<(), Error> {
    // TODO:
    Ok(())
}
