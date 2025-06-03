extern crate alloc;
use core::convert::TryInto;
use molecule::lazy_reader::{Cursor, Error, NUMBER_SIZE};
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
#[derive(Clone)]
pub struct Uint8Vec {
    pub cursor: Cursor,
}
impl From<Cursor> for Uint8Vec {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
impl Uint8Vec {
    pub fn len(&self) -> Result<usize, Error> {
        self.cursor.fixvec_length()
    }
}
impl Uint8Vec {
    pub fn get(&self, index: usize) -> Result<u8, Error> {
        let cur = self.cursor.fixvec_slice_by_index(1usize, index)?;
        cur.try_into()
    }
}
pub struct Uint8VecIterator {
    cur: Uint8Vec,
    index: usize,
    len: usize,
}
impl core::iter::Iterator for Uint8VecIterator {
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
impl core::iter::IntoIterator for Uint8Vec {
    type Item = u8;
    type IntoIter = Uint8VecIterator;
    fn into_iter(self) -> Self::IntoIter {
        let len = self.len().unwrap();
        Self::IntoIter {
            cur: self,
            index: 0,
            len,
        }
    }
}
pub struct Uint8VecIteratorRef<'a> {
    cur: &'a Uint8Vec,
    index: usize,
    len: usize,
}
impl<'a> core::iter::Iterator for Uint8VecIteratorRef<'a> {
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
impl Uint8Vec {
    pub fn iter(&self) -> Uint8VecIteratorRef {
        let len = self.len().unwrap();
        Uint8VecIteratorRef {
            cur: &self,
            index: 0,
            len,
        }
    }
}
impl Uint8Vec {
    pub fn verify(&self, _compatible: bool) -> Result<(), Error> {
        self.cursor.verify_fixvec(1usize)?;
        Ok(())
    }
}
#[derive(Clone)]
pub struct BytesVec {
    pub cursor: Cursor,
}
impl From<Cursor> for BytesVec {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
impl BytesVec {
    pub fn len(&self) -> Result<usize, Error> {
        self.cursor.dynvec_length()
    }
}
impl BytesVec {
    pub fn get(&self, index: usize) -> Result<Cursor, Error> {
        let cur = self.cursor.dynvec_slice_by_index(index)?;
        cur.convert_to_rawbytes()
    }
}
pub struct BytesVecIterator {
    cur: BytesVec,
    index: usize,
    len: usize,
}
impl core::iter::Iterator for BytesVecIterator {
    type Item = Cursor;
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
impl core::iter::IntoIterator for BytesVec {
    type Item = Cursor;
    type IntoIter = BytesVecIterator;
    fn into_iter(self) -> Self::IntoIter {
        let len = self.len().unwrap();
        Self::IntoIter {
            cur: self,
            index: 0,
            len,
        }
    }
}
pub struct BytesVecIteratorRef<'a> {
    cur: &'a BytesVec,
    index: usize,
    len: usize,
}
impl<'a> core::iter::Iterator for BytesVecIteratorRef<'a> {
    type Item = Cursor;
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
impl BytesVec {
    pub fn iter(&self) -> BytesVecIteratorRef {
        let len = self.len().unwrap();
        BytesVecIteratorRef {
            cur: &self,
            index: 0,
            len,
        }
    }
}
impl BytesVec {
    pub fn verify(&self, _compatible: bool) -> Result<(), Error> {
        self.cursor.verify_dynvec()?;
        Ok(())
    }
}
#[derive(Clone)]
pub struct OffidAuthorization {
    pub cursor: Cursor,
}
impl From<Cursor> for OffidAuthorization {
    fn from(cursor: Cursor) -> Self {
        OffidAuthorization { cursor }
    }
}
impl OffidAuthorization {
    pub fn history(&self) -> Result<BytesVec, Error> {
        let cur = self.cursor.table_slice_by_index(0usize)?;
        Ok(cur.into())
    }
}
impl OffidAuthorization {
    pub fn sig(&self) -> Result<Cursor, Error> {
        let cur = self.cursor.table_slice_by_index(1usize)?;
        cur.convert_to_rawbytes()
    }
}
impl OffidAuthorization {
    pub fn signing_keys(&self) -> Result<Cursor, Error> {
        let cur = self.cursor.table_slice_by_index(2usize)?;
        cur.convert_to_rawbytes()
    }
}
impl OffidAuthorization {
    pub fn verify(&self, compatible: bool) -> Result<(), Error> {
        self.cursor.verify_table(3usize, compatible)?;
        self.history()?.verify(compatible)?;
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
pub struct WitnessArgs {
    pub cursor: Cursor,
}
impl From<Cursor> for WitnessArgs {
    fn from(cursor: Cursor) -> Self {
        WitnessArgs { cursor }
    }
}
impl WitnessArgs {
    pub fn lock(&self) -> Result<Option<Cursor>, Error> {
        let cur = self.cursor.table_slice_by_index(0usize)?;
        if cur.option_is_none() {
            Ok(None)
        } else {
            let cur = cur.convert_to_rawbytes()?;
            Ok(Some(cur.into()))
        }
    }
}
impl WitnessArgs {
    pub fn input_type(&self) -> Result<Option<Cursor>, Error> {
        let cur = self.cursor.table_slice_by_index(1usize)?;
        if cur.option_is_none() {
            Ok(None)
        } else {
            let cur = cur.convert_to_rawbytes()?;
            Ok(Some(cur.into()))
        }
    }
}
impl WitnessArgs {
    pub fn output_type(&self) -> Result<Option<Cursor>, Error> {
        let cur = self.cursor.table_slice_by_index(2usize)?;
        if cur.option_is_none() {
            Ok(None)
        } else {
            let cur = cur.convert_to_rawbytes()?;
            Ok(Some(cur.into()))
        }
    }
}
impl WitnessArgs {
    pub fn verify(&self, compatible: bool) -> Result<(), Error> {
        self.cursor.verify_table(3usize, compatible)?;
        Ok(())
    }
}
