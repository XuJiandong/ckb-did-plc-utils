use ckb_std::ckb_constants::Source;

use crate::error::Error;
use crate::molecules::{new_data, new_witness};

pub fn entry() -> Result<(), Error> {
    let _data = new_data(0, Source::GroupOutput)?;
    let _witness = new_witness()?;
    Ok(())
}
