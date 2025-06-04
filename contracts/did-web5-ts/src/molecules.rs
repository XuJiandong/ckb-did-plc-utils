#![allow(unused_imports)]
#![allow(dead_code)]

mod cell_data;
mod witness;

use crate::error::Error;
use alloc::{boxed::Box, vec::Vec};
use ckb_did_plc_utils::cbor4ii::core::{dec::Decode, utils::SliceReader, Value};
use ckb_std::{ckb_constants::Source, error::SysError, syscalls};
use core::cmp::min;

pub use cell_data::*;
pub use molecule::lazy_reader::{Cursor, Error as MoleculeError, Read};
pub use witness::*;

fn read_data<F: Fn(&mut [u8], usize) -> Result<usize, SysError>>(
    load_func: F,
    buf: &mut [u8],
    offset: usize,
    total_size: usize,
) -> Result<usize, MoleculeError> {
    if offset >= total_size {
        return Err(MoleculeError::OutOfBound(offset, total_size));
    }
    match load_func(buf, offset) {
        Ok(l) => Ok(l),
        Err(err) => match err {
            SysError::LengthNotEnough(_) => Ok(buf.len()),
            _ => return Err(MoleculeError::OutOfBound(0, 0)),
        },
    }
}

fn read_size<F: Fn(&mut [u8]) -> Result<usize, SysError>>(
    load_func: F,
) -> Result<usize, MoleculeError> {
    let mut buf = [0u8; 4];
    match load_func(&mut buf) {
        Ok(l) => Ok(l),
        Err(e) => match e {
            SysError::LengthNotEnough(l) => Ok(l),
            _ => Err(MoleculeError::OutOfBound(0, 0)),
        },
    }
}

struct OnidReader {
    total_size: usize,
    index: usize,
    source: Source,
}

impl OnidReader {
    pub fn new(index: usize, source: Source) -> Self {
        let total_size = read_size(|buf| syscalls::load_cell_data(buf, 0, index, source)).unwrap();
        Self {
            total_size,
            source,
            index,
        }
    }
}

impl Read for OnidReader {
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, MoleculeError> {
        read_data(
            |buf, offset| syscalls::load_cell_data(buf, offset, self.index, self.source),
            buf,
            offset,
            self.total_size,
        )
    }
}

impl From<OnidReader> for Cursor {
    fn from(data: OnidReader) -> Self {
        Cursor::new(data.total_size, Box::new(data))
    }
}

pub fn new_onid(index: usize, source: Source) -> Result<cell_data::Onid, Error> {
    let reader = OnidReader::new(index, source);
    let cursor: Cursor = reader.into();
    let onid = cell_data::Onid::from(cursor);
    // the molecule format should be compatible when cells are upgraded.
    // TODO: add tests
    onid.verify(true)?;

    let doc = onid.document()?;
    let doc = doc.ok_or(Error::InvalidDocumentCbor)?;
    let doc: Vec<u8> = doc.try_into().map_err(|_| Error::InvalidDocumentCbor)?;

    // check that the document with cbor format
    let mut reader = SliceReader::new(&doc);
    let _ = Value::decode(&mut reader).map_err(|_| Error::InvalidDocumentCbor)?;

    Ok(onid)
}

struct WitnessArgsReader {
    total_size: usize,
    index: usize,
    source: Source,
}

impl WitnessArgsReader {
    fn new(index: usize, source: Source) -> Self {
        let total_size = read_size(|buf| syscalls::load_witness(buf, 0, index, source)).unwrap();
        Self {
            total_size,
            source,
            index,
        }
    }
}

impl Read for WitnessArgsReader {
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, MoleculeError> {
        read_data(
            |buf, offset| syscalls::load_witness(buf, offset, self.index, self.source),
            buf,
            offset,
            self.total_size,
        )
    }
}

impl From<WitnessArgsReader> for Cursor {
    fn from(data: WitnessArgsReader) -> Self {
        Cursor::new(data.total_size, Box::new(data))
    }
}

pub fn new_witness_args(index: usize, source: Source) -> Result<witness::WitnessArgs, Error> {
    let reader = WitnessArgsReader::new(index, source);
    let cursor: Cursor = reader.into();
    let witness_args = witness::WitnessArgs::from(cursor);
    witness_args.verify(false)?;
    Ok(witness_args)
}

pub fn new_offid_authorization() -> Result<witness::OffidAuthorization, Error> {
    let witness_args = new_witness_args(0, Source::GroupOutput)?;
    let output_type = witness_args.output_type()?;
    let output_type = output_type.ok_or(Error::Molecule)?;
    let offid_authorization = witness::OffidAuthorization::from(output_type);
    // The authorization data doesn't require compatible format
    offid_authorization.verify(false)?;
    Ok(offid_authorization)
}
