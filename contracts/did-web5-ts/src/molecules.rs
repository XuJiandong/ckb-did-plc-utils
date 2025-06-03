#![allow(unused_imports)]
#![allow(dead_code)]

mod cell_data;
mod witness;

use core::cmp::min;

use alloc::boxed::Box;
pub use cell_data::*;
use ckb_std::{ckb_constants::Source, error::SysError, syscalls};
pub use molecule::lazy_reader::{Cursor, Error, Read};
pub use witness::*;

fn read_data<F: Fn(&mut [u8], usize) -> Result<usize, SysError>>(
    load_func: F,
    buf: &mut [u8],
    offset: usize,
    total_size: usize,
) -> Result<usize, Error> {
    if offset >= total_size {
        return Err(Error::OutOfBound(offset, total_size));
    }
    let remaining_len = total_size - offset;
    let min_len = min(remaining_len, buf.len());
    if (offset + min_len) > total_size {
        return Err(Error::OutOfBound(offset + min_len, total_size));
    }
    let actual_len = match load_func(buf, offset) {
        Ok(l) => l,
        Err(err) => match err {
            SysError::LengthNotEnough(l) => l,
            _ => return Err(Error::OutOfBound(0, 0)),
        },
    };
    let read_len = min(buf.len(), actual_len);
    Ok(read_len)
}

fn read_size<F: Fn(&mut [u8]) -> Result<usize, SysError>>(load_func: F) -> Result<usize, Error> {
    let mut buf = [0u8; 4];
    match load_func(&mut buf) {
        Ok(l) => Ok(l),
        Err(e) => match e {
            SysError::LengthNotEnough(l) => Ok(l),
            _ => Err(Error::OutOfBound(0, 0)),
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
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Error> {
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

pub fn new_onid(index: usize, source: Source) -> cell_data::Onid {
    let reader = OnidReader::new(index, source);
    let cursor: Cursor = reader.into();
    cell_data::Onid::from(cursor)
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
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Error> {
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

pub fn new_witness_args(index: usize, source: Source) -> witness::WitnessArgs {
    let reader = WitnessArgsReader::new(index, source);
    let cursor: Cursor = reader.into();
    witness::WitnessArgs::from(cursor)
}
