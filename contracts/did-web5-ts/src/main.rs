#![no_std]
#![no_main]

mod entry;
mod error;
mod molecules;

ckb_std::entry!(program_entry);
ckb_std::default_alloc!(16384, 1258306, 64);

pub fn program_entry() -> i8 {
    #[cfg(feature = "enable_log")]
    {
        drop(ckb_std::logger::init());
        log::info!("did-web5-ts, log enabled");
    }
    match entry::entry() {
        Ok(_) => 0,
        Err(e) => {
            #[cfg(feature = "enable_log")]
            log::error!("error: {:?}", e);
            e.error_code()
        }
    }
}
