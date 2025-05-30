use crate::error::Error;
use alloc::vec::Vec;
use multibase::Base::Base58Btc;

pub(crate) struct PublicKey {
    // compressed public key
    pubkey: Vec<u8>,
    // if false, it is secp256r1
    is_secp256k1: bool,
}

// https://atproto.com/specs/cryptography
// it only supports base58btc.
pub fn decode_base58btc(input: &str) -> Result<Vec<u8>, Error> {
    let code = input.chars().next().ok_or(Error::InvalidKey)?;
    if code != 'z' {
        return Err(Error::InvalidKey);
    }
    let decoded = Base58Btc
        .decode(&input[code.len_utf8()..])
        .map_err(|_| Error::InvalidKey)?;
    Ok(decoded)
}

impl PublicKey {
    #[allow(dead_code)]
    pub(crate) fn raw(&self) -> &[u8] {
        &self.pubkey
    }
    pub(crate) fn from_str(key: &str) -> Result<Self, Error> {
        if !key.starts_with("did:key:") {
            return Err(Error::InvalidKey);
        }
        let key = key.split_at(8).1;
        let raw_pubkey = decode_base58btc(key)?;
        let is_secp256k1 = raw_pubkey[0] == 0xE7 && raw_pubkey[1] == 0x01;
        if !is_secp256k1 && (raw_pubkey[0] != 0x80 || raw_pubkey[1] != 0x24) {
            return Err(Error::InvalidKey);
        }
        let pubkey = raw_pubkey[2..].to_vec();
        if pubkey.len() != 33 {
            return Err(Error::InvalidKey);
        }
        Ok(PublicKey {
            pubkey,
            is_secp256k1,
        })
    }
    pub(crate) fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        if self.is_secp256k1 {
            use k256::ecdsa::signature::Verifier;
            let sig =
                k256::ecdsa::Signature::from_slice(sig).map_err(|_| Error::InvalidSignature)?;
            let pubkey = k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.pubkey)
                .map_err(|_| Error::InvalidKey)?;
            pubkey
                .verify(msg, &sig)
                .map_err(|_| Error::InvalidSignature)
        } else {
            use p256::ecdsa::signature::Verifier;
            let sig =
                p256::ecdsa::Signature::from_slice(sig).map_err(|_| Error::InvalidSignature)?;
            let pubkey = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.pubkey)
                .map_err(|_| Error::InvalidKey)?;
            pubkey
                .verify(msg, &sig)
                .map_err(|_| Error::InvalidSignature)
        }
    }
}
