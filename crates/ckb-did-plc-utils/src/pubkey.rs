use crate::error::Error;
use alloc::vec::Vec;
use multibase::decode;

pub(crate) struct PublicKey {
    // compressed public key
    pubkey: Vec<u8>,
    // if false, it is secp256r1
    is_secp256k1: bool,
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
        // TODO: improve it with base58btc only, reduce code size
        let (_, raw_pubkey) = decode(key).map_err(|_| Error::InvalidKey)?;
        let is_secp256k1 = raw_pubkey[0] == 0xE7 && raw_pubkey[1] == 0x01;
        if !is_secp256k1 {
            if raw_pubkey[0] != 0x80 || raw_pubkey[1] != 0x24 {
                return Err(Error::InvalidKey);
            }
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
