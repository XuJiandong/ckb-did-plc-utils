#![no_std]
#![no_main]

mod entry;
mod error;
ckb_std::entry!(program_entry);
ckb_std::default_alloc!(16384, 1258306, 64);

pub fn program_entry() -> i8 {
    #[cfg(feature = "log")]
    {
        drop(ckb_std::logger::init());
        log::info!("ckb-did-plc-registry, log enabled");
    }
    match entry::entry() {
        Ok(_) => 0,
        Err(e) => {
            #[cfg(feature = "log")]
            log::error!("error: {:?}", e);
            e.get_error_code()
        }
    }
}
