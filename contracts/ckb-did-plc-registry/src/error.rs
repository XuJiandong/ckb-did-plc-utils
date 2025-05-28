use ckb_did_plc_utils::error::Error as UtilsError;
use ckb_std::error::SysError;

#[derive(Debug)]
pub enum Error {
    Syscall(SysError),
    Utils(UtilsError),
    InvalidScriptOp,
    InvalidCell,
    InvalidDid,
}

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

impl Error {
    pub fn get_error_code(&self) -> i8 {
        match self {
            // ckb syserror starts from 21
            Error::Syscall(e) => match e {
                SysError::IndexOutOfBound => 21,
                SysError::ItemMissing => 22,
                SysError::LengthNotEnough(_) => 23,
                SysError::Encoding => 24,
                SysError::WaitFailure => 25,
                _ => 26,
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
            },
            // this script error starts from 51
            Error::InvalidScriptOp => 51,
            Error::InvalidCell => 52,
            Error::InvalidDid => 53,
        }
    }
}
