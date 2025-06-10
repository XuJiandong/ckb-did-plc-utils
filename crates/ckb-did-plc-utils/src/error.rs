use core::fmt::Display;
use molecule::lazy_reader::Error as MoleculeError;

#[derive(Debug)]
pub enum Error {
    InvalidOperation,
    RotationKeysDecodeError,
    InvalidKey,
    InvalidKeyIndex,
    InvalidSignature,
    InvalidSignaturePadding,
    VerifySignatureFailed,
    InvalidPrev,
    NotGenesisOperation,
    DidMismatched,
    ReaderError,
    InvalidHistory,
    MoleculeError(MoleculeError),
}

impl From<MoleculeError> for Error {
    fn from(value: MoleculeError) -> Self {
        Error::MoleculeError(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl core::error::Error for Error {}
