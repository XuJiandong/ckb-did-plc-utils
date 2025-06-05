use core::fmt::Display;

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
    ReaderError,
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl core::error::Error for Error {}
