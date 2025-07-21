use crate::error::Error;
use alloc::vec::Vec;
use cbor4ii::core::{Value, dec::Decode, utils::SliceReader};
use molecule::lazy_reader::Cursor;

pub fn validate_cbor_format(cur: Cursor) -> Result<(), Error> {
    let buf: Vec<u8> = cur.try_into()?;
    let mut reader = SliceReader::new(&buf);
    let _ = Value::decode(&mut reader).map_err(|_| Error::InvalidCbor)?;
    Ok(())
}
