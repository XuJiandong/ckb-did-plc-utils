use ckb_did_plc_utils::error::Error as UtilsError;
use ckb_std::error::SysError;
use core::fmt::Display;
use molecule::lazy_reader::Error as MoleculeError;

#[derive(Debug)]
pub enum Error {
    Syscall(SysError),
    Utils(UtilsError),
    Molecule,
    InvalidDocumentCbor,
    MismatchedFrom,
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl core::error::Error for Error {}

impl From<SysError> for Error {
    fn from(e: SysError) -> Self {
        Error::Syscall(e)
    }
}

impl From<UtilsError> for Error {
    fn from(e: UtilsError) -> Self {
        Error::Utils(e)
    }
}

impl From<MoleculeError> for Error {
    fn from(_: MoleculeError) -> Self {
        Error::Molecule
    }
}

impl Error {
    pub fn error_code(&self) -> i8 {
        match self {
            // ckb syserror starts from 21
            Error::Syscall(e) => match e {
                SysError::IndexOutOfBound => 21,
                SysError::ItemMissing => 22,
                SysError::LengthNotEnough(_) => 23,
                SysError::Encoding => 24,
                SysError::WaitFailure => 25,
                SysError::TypeIDError => 26,
                _ => 27,
            },
            // crate ckb-did-plc-utils error starts from 31
            Error::Utils(e) => match e {
                UtilsError::InvalidOperation => 31,
                UtilsError::RotationKeysDecodeError => 32,
                UtilsError::InvalidKey => 33,
                UtilsError::InvalidSignature => 34,
                UtilsError::InvalidSignaturePadding => 35,
                UtilsError::VerifySignatureFailed => 36,
                UtilsError::InvalidPrev => 37,
                UtilsError::NotGenesisOperation => 38,
                UtilsError::DidMismatched => 39,
                UtilsError::ReaderError => 40,
                UtilsError::InvalidKeyIndex => 41,
                UtilsError::InvalidHistory => 42,
                UtilsError::MoleculeError(_) => 43,
                UtilsError::InvalidCbor => 44,
                UtilsError::InvalidDidFormat => 45,
            },
            // this script error starts from 51
            Error::Molecule => 51,
            Error::InvalidDocumentCbor => 52,
            Error::MismatchedFrom => 53,
        }
    }
}
