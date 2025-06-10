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
pub struct String {
    pub cursor: Cursor,
}
impl From<Cursor> for String {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
impl String {
    pub fn len(&self) -> Result<usize, Error> {
        self.cursor.fixvec_length()
    }
}
impl String {
    pub fn get(&self, index: usize) -> Result<u8, Error> {
        let cur = self.cursor.fixvec_slice_by_index(1usize, index)?;
        cur.try_into()
    }
}
pub struct StringIterator {
    cur: String,
    index: usize,
    len: usize,
}
impl core::iter::Iterator for StringIterator {
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
impl core::iter::IntoIterator for String {
    type Item = u8;
    type IntoIter = StringIterator;
    fn into_iter(self) -> Self::IntoIter {
        let len = self.len().unwrap();
        Self::IntoIter {
            cur: self,
            index: 0,
            len,
        }
    }
}
pub struct StringIteratorRef<'a> {
    cur: &'a String,
    index: usize,
    len: usize,
}
impl<'a> core::iter::Iterator for StringIteratorRef<'a> {
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
impl String {
    pub fn iter(&self) -> StringIteratorRef {
        let len = self.len().unwrap();
        StringIteratorRef {
            cur: &self,
            index: 0,
            len,
        }
    }
}
impl String {
    pub fn verify(&self, _compatible: bool) -> Result<(), Error> {
        self.cursor.verify_fixvec(1usize)?;
        Ok(())
    }
}
#[derive(Clone)]
pub struct StringVec {
    pub cursor: Cursor,
}
impl From<Cursor> for StringVec {
    fn from(cursor: Cursor) -> Self {
        Self { cursor }
    }
}
impl StringVec {
    pub fn len(&self) -> Result<usize, Error> {
        self.cursor.dynvec_length()
    }
}
impl StringVec {
    pub fn get(&self, index: usize) -> Result<Cursor, Error> {
        let cur = self.cursor.dynvec_slice_by_index(index)?;
        cur.convert_to_rawbytes()
    }
}
pub struct StringVecIterator {
    cur: StringVec,
    index: usize,
    len: usize,
}
impl core::iter::Iterator for StringVecIterator {
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
impl core::iter::IntoIterator for StringVec {
    type Item = Cursor;
    type IntoIter = StringVecIterator;
    fn into_iter(self) -> Self::IntoIter {
        let len = self.len().unwrap();
        Self::IntoIter {
            cur: self,
            index: 0,
            len,
        }
    }
}
pub struct StringVecIteratorRef<'a> {
    cur: &'a StringVec,
    index: usize,
    len: usize,
}
impl<'a> core::iter::Iterator for StringVecIteratorRef<'a> {
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
impl StringVec {
    pub fn iter(&self) -> StringVecIteratorRef {
        let len = self.len().unwrap();
        StringVecIteratorRef {
            cur: &self,
            index: 0,
            len,
        }
    }
}
impl StringVec {
    pub fn verify(&self, _compatible: bool) -> Result<(), Error> {
        self.cursor.verify_dynvec()?;
        Ok(())
    }
}
#[derive(Clone)]
pub struct DidWeb5DataV1 {
    pub cursor: Cursor,
}
impl From<Cursor> for DidWeb5DataV1 {
    fn from(cursor: Cursor) -> Self {
        DidWeb5DataV1 { cursor }
    }
}
impl DidWeb5DataV1 {
    pub fn document(&self) -> Result<Cursor, Error> {
        let cur = self.cursor.table_slice_by_index(0usize)?;
        cur.convert_to_rawbytes()
    }
}
impl DidWeb5DataV1 {
    pub fn transferred_from(&self) -> Result<StringVec, Error> {
        let cur = self.cursor.table_slice_by_index(1usize)?;
        Ok(cur.into())
    }
}
impl DidWeb5DataV1 {
    pub fn verify(&self, compatible: bool) -> Result<(), Error> {
        self.cursor.verify_table(2usize, compatible)?;
        self.transferred_from()?.verify(compatible)?;
        Ok(())
    }
}
pub enum DidWeb5Data {
    DidWeb5DataV1(DidWeb5DataV1),
}
impl TryFrom<Cursor> for DidWeb5Data {
    type Error = Error;
    fn try_from(cur: Cursor) -> Result<Self, Self::Error> {
        let item = cur.union_unpack()?;
        let mut cur = cur;
        cur.add_offset(NUMBER_SIZE)?;
        cur.sub_size(NUMBER_SIZE)?;
        match item.item_id {
            0usize => Ok(Self::DidWeb5DataV1(cur.into())),
            _ => Err(Error::UnknownItem),
        }
    }
}
impl DidWeb5Data {
    pub fn verify(&self, compatible: bool) -> Result<(), Error> {
        match self {
            Self::DidWeb5DataV1(v) => {
                v.verify(compatible)?;
                Ok(())
            }
        }
    }
}
