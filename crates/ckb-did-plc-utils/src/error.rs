#[derive(Debug)]
pub enum Error {
    InvalidOperation,
    RotationKeysDecodeError,
    InvalidKey,
    InvalidSignature,
}
