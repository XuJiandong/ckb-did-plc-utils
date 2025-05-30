use crate::error::Error;
use ckb_did_plc_utils::operation::{validate_2_operations, validate_genesis_operation};
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{QueryIter, load_cell_data, load_cell_lock, load_script},
    syscalls::load_cell,
};

const SCRIPT_ARGS_OP_DEFAULT: u8 = 1;

fn is_cell_present(index: usize, source: Source) -> bool {
    let buf = &mut [];
    matches!(
        load_cell(buf, 0, index, source),
        Ok(_) | Err(SysError::LengthNotEnough(_))
    )
}

fn default_entry() -> Result<(), Error> {
    let script = load_script()?;
    // 1. There's at most one input, and exactly one output in the script group.
    if is_cell_present(1, Source::GroupInput) || is_cell_present(1, Source::GroupOutput) {
        #[cfg(feature = "enable_log")]
        log::warn!("invalid cells");
        return Err(Error::InvalidCell);
    }
    if !is_cell_present(0, Source::GroupOutput) {
        #[cfg(feature = "enable_log")]
        log::warn!("no output cell found");
        return Err(Error::InvalidCell);
    }

    // 2. All cells in the script group must use R(OP | did) as the type script, and R(OP | did) as the lock script.
    for lock in QueryIter::new(load_cell_lock, Source::GroupInput)
        .chain(QueryIter::new(load_cell_lock, Source::GroupOutput))
    {
        if lock.code_hash() != script.code_hash() || lock.hash_type() != script.hash_type() {
            return Err(Error::InvalidCell);
        }
        if !lock.args().raw_data().is_empty() {
            return Err(Error::InvalidCell);
        }
    }

    if !is_cell_present(0, Source::GroupInput) {
        // genesis operation
        // 3. When there is no inputs in the cell group:
        // a. The output is a valid genesis operation serialized in DAG-CBOR.
        // b. The field `did` in args matches the genesis operation.
        // c. The field `signature`in the genesis operation MUST be a valid signature of the unsigned genesis operation signed by a key listed in the field `rotationKeys` of the genesis operation.
        let binary_did = script.args().raw_data()[1..].to_vec();
        if binary_did.len() != 15 {
            return Err(Error::InvalidDid);
        }
        let data = load_cell_data(0, Source::GroupOutput)?;
        validate_genesis_operation(&data, &binary_did)?;
    } else {
        // update operation
        // 4. When there is an input in the cell group:
        // a. The output is either a well-formatted update or deactivation operation in DAG-CBOR.
        // b. The field `prev` of the output operation is the CID of the input operation.
        // c. The field `signature`in the output operation MUST be a valid signature of the unsigned output operation signed by a key listed in the field `rotationKeys` of the input operation.
        let prev_data = load_cell_data(0, Source::GroupInput)?;
        let cur_data = load_cell_data(0, Source::GroupOutput)?;
        validate_2_operations(&prev_data, &cur_data)?;
    }

    Ok(())
}

pub fn entry() -> Result<(), Error> {
    let script = load_script()?;
    let args = script.args().raw_data();
    // always success
    if args.is_empty() {
        return Ok(());
    }
    match args[0] {
        SCRIPT_ARGS_OP_DEFAULT => default_entry(),
        _ => {
            #[cfg(feature = "enable_log")]
            log::warn!("invalid script op: {}", args[0]);
            Err(Error::InvalidScriptOp)
        }
    }
}
