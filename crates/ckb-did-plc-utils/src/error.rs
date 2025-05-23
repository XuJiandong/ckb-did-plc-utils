#[derive(Debug)]
pub enum Error {
    InvalidOperation,
    RotationKeysDecodeError,
    InvalidKey,
    InvalidSignature,
    InvalidSignaturePadding,
    VerifySignatureFailed,
    InvalidPrev,
    NotGenesisOperation,
    DidMismatched,
}
