extern crate alloc;
use core::convert::TryInto;
use molecule::lazy_reader::{Cursor, Error, NUMBER_SIZE};
#[derive(Clone)]
pub struct Byte15 {
    pub cursor: Cursor,
}
impl From<Cursor> for Byte15 {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
impl Byte15 {
    pub fn len(&self) -> usize {
        15
    }
}
impl Byte15 {
    pub fn get(&self, index: usize) -> Result<u8, Error> {
        let cur = self.cursor.slice_by_offset(1usize * index, 1usize)?;
        cur.try_into()
    }
}
impl Byte15 {
    pub fn verify(&self, _compatible: bool) -> Result<(), Error> {
        self.cursor.verify_fixed_size(15usize)?;
        Ok(())
    }
}
pub struct Byte15Opt {
    pub cursor: Cursor,
}
impl From<Cursor> for Byte15Opt {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
#[derive(Clone)]
pub struct Bytes {
    pub cursor: Cursor,
}
impl From<Cursor> for Bytes {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
impl Bytes {
    pub fn len(&self) -> Result<usize, Error> {
        self.cursor.fixvec_length()
    }
}
impl Bytes {
    pub fn get(&self, index: usize) -> Result<u8, Error> {
        let cur = self.cursor.fixvec_slice_by_index(1usize, index)?;
        cur.try_into()
    }
}
pub struct BytesIterator {
    cur: Bytes,
    index: usize,
    len: usize,
}
impl core::iter::Iterator for BytesIterator {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.len {
            None
        } else {
            let res = self.cur.get(self.index).unwrap();
            self.index += 1;
            Some(res)
        }
    }
}
impl core::iter::IntoIterator for Bytes {
    type Item = u8;
    type IntoIter = BytesIterator;
    fn into_iter(self) -> Self::IntoIter {
        let len = self.len().unwrap();
        Self::IntoIter {
            cur: self,
            index: 0,
            len,
        }
    }
}
pub struct BytesIteratorRef<'a> {
    cur: &'a Bytes,
    index: usize,
    len: usize,
}
impl<'a> core::iter::Iterator for BytesIteratorRef<'a> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.len {
            None
        } else {
            let res = self.cur.get(self.index).unwrap();
            self.index += 1;
            Some(res)
        }
    }
}
impl Bytes {
    pub fn iter(&self) -> BytesIteratorRef {
        let len = self.len().unwrap();
        BytesIteratorRef {
            cur: &self,
            index: 0,
            len,
        }
    }
}
impl Bytes {
    pub fn verify(&self, _compatible: bool) -> Result<(), Error> {
        self.cursor.verify_fixvec(1usize)?;
        Ok(())
    }
}
pub struct BytesOpt {
    pub cursor: Cursor,
}
impl From<Cursor> for BytesOpt {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
#[derive(Clone)]
pub struct Onid {
    pub cursor: Cursor,
}
impl From<Cursor> for Onid {
    fn from(cursor: Cursor) -> Self {
        Onid { cursor }
    }
}
impl Onid {
    pub fn offid(&self) -> Result<Option<[u8; 15usize]>, Error> {
        let cur = self.cursor.table_slice_by_index(0usize)?;
        if cur.option_is_none() {
            Ok(None)
        } else {
            Ok(Some(cur.try_into()?))
        }
    }
}
impl Onid {
    pub fn document(&self) -> Result<Option<Cursor>, Error> {
        let cur = self.cursor.table_slice_by_index(1usize)?;
        if cur.option_is_none() {
            Ok(None)
        } else {
            let cur = cur.convert_to_rawbytes()?;
            Ok(Some(cur.into()))
        }
    }
}
impl Onid {
    pub fn verify(&self, compatible: bool) -> Result<(), Error> {
        self.cursor.verify_table(2usize, compatible)?;
        let val = self.offid()?;
        if val.is_some() {
            let val = val.unwrap();
            Byte15::from(Cursor::try_from(val)?).verify(compatible)?;
        }
        Ok(())
    }
}
