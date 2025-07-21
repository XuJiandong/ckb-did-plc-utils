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
use molecule::lazy_reader::Cursor;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::pubkey::PublicKey;

// this is the only one valid local id so far
const LOCAL_ID_PREFIX: &str = "did:plc:";

pub fn parse_local_id(id: &[u8]) -> Result<Vec<u8>, Error> {
    let str = core::str::from_utf8(id).map_err(|_| Error::InvalidDidFormat)?;
    if let Some(str) = str.strip_prefix(LOCAL_ID_PREFIX) {
        base32::decode(Alphabet::Rfc4648Lower { padding: false }, str)
            .ok_or(Error::InvalidDidFormat)
    } else {
        Err(Error::InvalidDidFormat)
    }
}

pub(crate) struct Operation {
    raw: Value,
    cached_keys: Vec<String>,
}

impl Operation {
    pub(crate) fn from_slice(buf: &[u8]) -> Result<Self, Error> {
        let mut reader = SliceReader::new(buf);
        let raw = Value::decode(&mut reader).map_err(|_| Error::InvalidOperation)?;
        let mut op = Operation {
            raw,
            cached_keys: vec![],
        };
        op.update_cached_keys()?;
        Ok(op)
    }
    pub(crate) fn update_cached_keys(&mut self) -> Result<(), Error> {
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

    pub(crate) fn new_unsigned_operation(&self) -> Result<Self, Error> {
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
    pub(crate) fn validate(&self) -> Result<(), Error> {
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
                Ok(())
            } else {
                Err(Error::InvalidOperation)
            }
        } else if self.is_operation() {
            if self.has_keys(&[
                "type",
                "rotationKeys",
                "verificationMethods",
                "alsoKnownAs",
                "services",
                "prev",
                "sig",
            ]) {
                Ok(())
            } else {
                Err(Error::InvalidOperation)
            }
        } else {
            Err(Error::InvalidOperation)
        }
    }
    pub(crate) fn is_operation(&self) -> bool {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Text(value)) = (k, v) {
                    if key == "type" && value == "plc_operation" {
                        return true;
                    }
                }
            }
        }
        false
    }
    pub(crate) fn is_legacy(&self) -> bool {
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
    pub(crate) fn get_rotation_keys(&self) -> Result<Vec<PublicKey>, Error> {
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
    // "signingKey" and "recoveryKey" are both used as rotation keys for legacy operation
    pub(crate) fn get_legacy_rotation_keys(&self) -> Result<Vec<PublicKey>, Error> {
        let mut pubkeys = vec![];
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Text(value)) = (k, v) {
                    if key == "signingKey" || key == "recoveryKey" {
                        pubkeys.push(PublicKey::from_str(value)?);
                    }
                }
            }
        }
        Ok(pubkeys)
    }

    pub(crate) fn get_signature(&self) -> Result<Vec<u8>, Error> {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let (Value::Text(key), Value::Text(value)) = (k, v) {
                    if key == "sig" {
                        // https://github.com/did-method-plc/did-method-plc/blob/bd5825589a34d1abb377943389ac3838a15cd110/packages/lib/src/operations.ts#L268
                        if value.ends_with("=") {
                            return Err(Error::InvalidSignaturePadding);
                        }
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
    pub(crate) fn verify_signature(
        &self,
        pubkeys: &[PublicKey],
        rotation_key_index: usize,
    ) -> Result<(), Error> {
        let unsigned_op = self.new_unsigned_operation()?;
        let sig = self.get_signature()?;
        let mut writer = BufWriter::new(Vec::new());
        unsigned_op
            .raw
            .encode(&mut writer)
            .map_err(|_| Error::InvalidOperation)?;
        let msg = writer.into_inner();
        if rotation_key_index >= pubkeys.len() {
            return Err(Error::InvalidKeyIndex);
        }
        if pubkeys[rotation_key_index].verify(&msg, &sig).is_ok() {
            Ok(())
        } else {
            #[cfg(feature = "enable_log")]
            {
                log::warn!("verify signature failed");
                log::warn!("sig: (length = {}), {}", sig.len(), hex::encode(sig));
                log::warn!("msg: (length = {}), {}", msg.len(), hex::encode(msg));
                log::warn!("rotation_key_index = {}", rotation_key_index);
                for pubkey in pubkeys {
                    let pubkey = pubkey.raw();
                    log::warn!(
                        "pubkey: (length = {}), {}",
                        pubkey.len(),
                        hex::encode(pubkey)
                    );
                }
            }
            Err(Error::VerifySignatureFailed)
        }
    }
    pub(crate) fn generate_cid(&self) -> Result<String, Error> {
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

    // The `prev` field can be null for genesis operation
    pub(crate) fn get_prev(&self) -> Result<Option<String>, Error> {
        if let Value::Map(map) = &self.raw {
            for (k, v) in map {
                if let Value::Text(key) = k {
                    if key == "prev" {
                        if let Value::Text(value) = v {
                            return Ok(Some(value.clone()));
                        } else if let Value::Null = v {
                            return Ok(None);
                        } else {
                            return Err(Error::InvalidOperation);
                        }
                    }
                }
            }
        }
        Err(Error::InvalidOperation)
    }
    #[allow(unused)]
    pub(crate) fn get_did(&self) -> Result<String, Error> {
        let binary_did = self.get_binary_did()?;
        let b32 = base32::encode(
            Alphabet::Rfc4648Lower { padding: false },
            binary_did.as_slice(),
        );
        Ok(format!("did:plc:{}", b32))
    }
    pub(crate) fn get_binary_did(&self) -> Result<Vec<u8>, Error> {
        let mut writer = BufWriter::new(Vec::new());
        self.raw
            .encode(&mut writer)
            .map_err(|_| Error::InvalidOperation)?;
        let dag = writer.into_inner();
        let hashed = Sha256::digest(dag.as_slice());
        // The identifier part is 24 characters long, including only characters from the base32 encoding set.
        // Which means the binary size is 15 bytes.
        Ok(hashed[0..15].to_vec())
    }

    fn has_keys(&self, keys: &[&str]) -> bool {
        keys.iter()
            .all(|&key| self.cached_keys.iter().any(|k| k == key))
    }
}

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
pub fn validate_2_operations(
    prev_buf: &[u8],
    cur_buf: &[u8],
    rotation_key_index: usize,
) -> Result<(), Error> {
    let prev_op = Operation::from_slice(prev_buf)?;
    let cur_op = Operation::from_slice(cur_buf)?;
    prev_op.validate()?;
    cur_op.validate()?;
    let cid = prev_op.generate_cid()?;
    match cur_op.get_prev()? {
        Some(prev) => {
            if prev != cid {
                #[cfg(feature = "enable_log")]
                {
                    log::warn!("invalid prev");
                    log::warn!("cid: {}", cid);
                    log::warn!("prev: {}", prev);
                }
                return Err(Error::InvalidPrev);
            }
        }
        None => return Err(Error::MissingPrevField),
    }
    let rotation_keys = if prev_op.is_legacy() {
        prev_op.get_legacy_rotation_keys()?
    } else {
        prev_op.get_rotation_keys()?
    };
    cur_op.verify_signature(&rotation_keys, rotation_key_index)?;
    Ok(())
}

pub fn validate_genesis_operation(
    buf: &[u8],
    binary_did: &[u8],
    rotation_key_index: usize,
) -> Result<(), Error> {
    let op = Operation::from_slice(buf)?;
    op.validate()?;
    let prev = op.get_prev()?;
    if prev.is_some() {
        return Err(Error::NotGenesisOperation);
    }
    let rotation_keys = if op.is_legacy() {
        op.get_legacy_rotation_keys()?
    } else {
        op.get_rotation_keys()?
    };
    op.verify_signature(&rotation_keys, rotation_key_index)?;
    let expected_did = op.get_binary_did()?;
    if binary_did != expected_did {
        #[cfg(feature = "enable_log")]
        {
            log::warn!("did mismatched");
            log::warn!("did: {:?}", binary_did);
            log::warn!("expected did: {:?}", expected_did);
        }
        return Err(Error::DidMismatched);
    }
    Ok(())
}

fn validate_final_operation(
    buf: &[u8],
    final_sig: &[u8],
    msg: &[u8],
    rotation_key_index: usize,
) -> Result<(), Error> {
    let op = Operation::from_slice(buf)?;
    let rotation_keys = op.get_rotation_keys()?;
    rotation_keys[rotation_key_index].verify(msg, final_sig)?;
    Ok(())
}

/// Validates a complete DID PLC operation history chain and final authorization signature.
///
/// This function performs comprehensive validation of a DID PLC operation history,
/// ensuring the integrity and authenticity of the entire operation chain from genesis
/// to the final on-chain authorization.
///
/// # Parameters
///
/// * `binary_did` - The expected binary DID identifier (15 bytes) that should match
///   the DID derived from the genesis operation
/// * `history` - A vector of operation cursors representing the complete operation
///   history chain, starting with the genesis operation
/// * `rotation_key_indices` - A vector of signing key indices used for signature verification.
///   The length must be `history.len() + 1` where:
///   - `rotation_key_indices[0]`: Index for genesis operation signature
///   - `rotation_key_indices[1..history_len]`: Indices for transitions between operations
///   - `rotation_key_indices[history_len]`: Index for final authorization signature
/// * `msg` - The message that was signed for the final authorization
/// * `final_sig` - The signature authorizing the DID PLC operation on-chain
///
pub fn validate_operation_history(
    binary_did: &[u8],
    history: Vec<Cursor>,
    rotation_key_indices: Vec<usize>,
    msg: &[u8],
    final_sig: &[u8],
) -> Result<(), Error> {
    let history_len = history.len();

    if history_len == 0 || (history_len + 1) != rotation_key_indices.len() {
        return Err(Error::InvalidHistory);
    }
    let genesis_operation: Vec<u8> = history[0].clone().try_into()?;
    // Signing key index mapping:
    // - rotation_key_indices[0]: Genesis operation
    // - rotation_key_indices[1]: Transition from operation[0] to operation[1]
    // - ...
    // - rotation_key_indices[history_len - 1]: Transition from operation[history_len-2] to operation[history_len-1]
    // - rotation_key_indices[history_len]: Final operation
    validate_genesis_operation(&genesis_operation, binary_did, rotation_key_indices[0])?;
    let mut prev = genesis_operation;
    for index in 1..history_len {
        let cur: Vec<u8> = history[index].clone().try_into()?;
        validate_2_operations(&prev, &cur, rotation_key_indices[index])?;
        prev = cur;
    }
    // Validate the final operation signature to authorize the did:plc operation on chain
    validate_final_operation(&prev, final_sig, msg, rotation_key_indices[history_len])?;
    Ok(())
}
