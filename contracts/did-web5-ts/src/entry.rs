use crate::error::Error;
use crate::molecules::{new_data, new_witness, PlcAuthorization};
use crate::type_id::{check_type_id, is_cell_present};
use alloc::vec::Vec;
use ckb_did_plc_utils::{
    operation::{parse_staging_id, validate_operation_history},
    reader::validate_cbor_format,
};
use ckb_std::{ckb_constants::Source, high_level::load_tx_hash};
use molecule::lazy_reader::Cursor;

fn mint() -> Result<(), Error> {
    let data = new_data(0, Source::GroupOutput)?;
    // validate cbor format
    validate_cbor_format(data.document()?)?;

    let staging_id = data.local_id()?;
    // Allow empty staging ID - this indicates the cell has no associated did:plc
    // and can be minted without requiring did:plc authorization
    if staging_id.is_none() {
        return Ok(());
    }
    let staging_id: Vec<u8> = staging_id.unwrap().try_into()?;

    let witness = new_witness()?;
    let auth: PlcAuthorization = witness.local_id_authorization()?;

    let binary_did = parse_staging_id(&staging_id)?;
    // History contains DID operations which can be very large. Using Cursor for lazy reading
    // to avoid loading the entire operation history into memory at once.
    let history: Vec<Cursor> = auth.history()?.into_iter().collect();
    let final_sig: Vec<u8> = auth.sig()?.try_into()?;
    let signing_key_index: Vec<u8> = auth.signing_keys()?.try_into()?;
    let signing_key_index: Vec<usize> = signing_key_index.into_iter().map(|e| e as usize).collect();
    let msg = load_tx_hash()?;
    validate_operation_history(&binary_did, history, signing_key_index, &msg, &final_sig)?;
    #[cfg(feature = "enable_log")]
    log::info!("validate operation history successfully");

    Ok(())
}

fn update() -> Result<(), Error> {
    let prev_data = new_data(0, Source::GroupInput)?;
    let cur_data = new_data(0, Source::GroupOutput)?;

    // validate formats of document
    validate_cbor_format(cur_data.document()?)?;
    validate_cbor_format(prev_data.document()?)?;

    let prev_from: Vec<Vec<u8>> = prev_data
        .local_id()?
        .into_iter()
        .map(|c| c.try_into().map_err(|_| Error::Molecule))
        .collect::<Result<Vec<_>, _>>()?;
    let cur_from: Vec<Vec<u8>> = cur_data
        .local_id()?
        .into_iter()
        .map(|c| c.try_into().map_err(|_| Error::Molecule))
        .collect::<Result<Vec<_>, _>>()?;
    if prev_from != cur_from {
        Err(Error::MismatchedFrom)
    } else {
        Ok(())
    }
}

fn burn() -> Result<(), Error> {
    Ok(())
}

pub fn entry() -> Result<(), Error> {
    check_type_id(0, 20)?;
    match (
        is_cell_present(0, Source::GroupInput),
        is_cell_present(0, Source::GroupOutput),
    ) {
        (true, true) => update(),
        (true, false) => burn(),
        (false, true) => mint(),
        (false, false) => unreachable!(),
    }
}
