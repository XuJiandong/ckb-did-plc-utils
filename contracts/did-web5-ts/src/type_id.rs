use alloc::vec::Vec;
use ckb_hash::new_blake2b;
use ckb_std::ckb_types::prelude::Entity;
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{load_cell_type_hash, load_input, load_script, load_script_hash, QueryIter},
    syscalls::load_cell,
};

pub fn is_cell_present(index: usize, source: Source) -> bool {
    let buf = &mut [];
    matches!(
        load_cell(buf, 0, index, source),
        Ok(_) | Err(SysError::LengthNotEnough(_))
    )
}

fn locate_index() -> Result<usize, SysError> {
    let hash = load_script_hash()?;

    let index = QueryIter::new(load_cell_type_hash, Source::Output)
        .position(|type_hash| type_hash == Some(hash))
        .ok_or(SysError::TypeIDError)?;

    Ok(index)
}

pub fn validate_type_id(type_id: &[u8]) -> Result<(), SysError> {
    // after this checking, there are 3 cases:
    // 1. 0 input cell and 1 output cell, it's minting operation
    // 2. 1 input cell and 1 output cell, it's transfer operation
    // 3. 1 input cell and 0 output cell, it's burning operation(allowed)
    if is_cell_present(1, Source::GroupInput) || is_cell_present(1, Source::GroupOutput) {
        return Err(SysError::TypeIDError);
    }

    // case 1: minting operation
    if !is_cell_present(0, Source::GroupInput) {
        let index = locate_index()? as u64;
        let input = load_input(0, Source::Input)?;
        let mut blake2b = new_blake2b();
        blake2b.update(input.as_slice());
        blake2b.update(&index.to_le_bytes());
        let mut ret = [0; 32];
        blake2b.finalize(&mut ret);

        if &ret[0..type_id.len()] != type_id {
            #[cfg(feature = "enable_log")]
            log::warn!(
                "type id mismatched: {} {}(expected)",
                hex::encode(&ret[0..type_id.len()]),
                hex::encode(&type_id)
            );
            return Err(SysError::TypeIDError);
        }
    }
    // case 2 & 3: for the `else` part, it's transfer operation or burning operation
    Ok(())
}

fn load_id_from_args(offset: usize, length: usize) -> Result<Vec<u8>, SysError> {
    let script = load_script()?;
    let args = script.as_reader().args();
    let args_data = args.raw_data();

    Ok(args_data
        .get(offset..offset + length)
        .ok_or(SysError::TypeIDError)?
        .to_vec())
}

pub fn check_type_id(offset: usize, length: usize) -> Result<(), SysError> {
    let type_id = load_id_from_args(offset, length)?;
    validate_type_id(&type_id)?;
    Ok(())
}
