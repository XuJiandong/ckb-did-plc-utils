use crate::error::Error;
use cbor4ii::core::dec::{self, Read};
use molecule::lazy_reader::Cursor;

pub struct ReadAdaptor {
    cursor: Cursor,
    buf: [u8; 1024],
    limit: usize,
}

impl ReadAdaptor {
    pub fn new(cursor: Cursor) -> Self {
        Self {
            cursor,
            buf: [0u8; 1024],
            limit: 256,
        }
    }
}

impl<'de> Read<'de> for ReadAdaptor {
    type Error = Error;

    #[inline]
    fn fill<'short>(
        &'short mut self,
        want: usize,
    ) -> Result<dec::Reference<'de, 'short>, Self::Error> {
        let len = core::cmp::min(self.buf.len(), want);
        let read_len = self
            .cursor
            .read_at(&mut self.buf[..len])
            .map_err(|_| Error::ReaderError)?;
        Ok(dec::Reference::Short(&self.buf[..read_len]))
    }

    #[inline]
    fn advance(&mut self, n: usize) {
        self.cursor.slice_by_start(n).unwrap();
    }

    #[inline]
    fn step_in(&mut self) -> bool {
        if let Some(limit) = self.limit.checked_sub(1) {
            self.limit = limit;
            true
        } else {
            false
        }
    }

    #[inline]
    fn step_out(&mut self) {
        self.limit += 1;
    }
}
