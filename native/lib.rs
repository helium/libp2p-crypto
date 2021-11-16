mod droptimer;
mod hbin;

use caches::{AdaptiveCache, Cache};
use hbin::HBin;
use helium_crypto::{ecc_compact::PublicKey, Verify};
use once_cell::sync::Lazy;
use rustler::{Atom, Binary, Error as NifError, ListIterator, NifResult};
use std::{convert::TryFrom, sync::Mutex};

// -spec verify(
//     Batch :: [{Bin :: binary(), [{Signature :: binary(), CompactEccKey :: binary()}, ...]}]
// ) -> ok | {error, Reason :: binary()}.
#[rustler::nif(name = "verify", schedule = "DirtyCpu")]
fn verify_1(batch: ListIterator) -> NifResult<Atom> {
    let _timer = droptimer::DropTimer::new();
    for sub_batch in batch.map(|term| term.decode::<(Binary, ListIterator)>()) {
        let (msg, list) = sub_batch?;
        for pair in list.map(|term| term.decode::<(Binary, Binary)>()) {
            let (signature, compact_key) = pair?;
            let compact_key = HBin::from(&compact_key);
            let mut cache = PK_CACHE.lock().unwrap();
            match cache.get(&compact_key) {
                Some(pk) => pk
                    .verify(msg.as_slice(), signature.as_slice())
                    .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?,
                None => {
                    let pk = PublicKey::try_from(compact_key.as_slice())
                        .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?;
                    let res = pk
                        .verify(msg.as_slice(), signature.as_slice())
                        .map_err(|e| NifError::Term(Box::new(format!("{}", e))));
                    cache.put(compact_key, pk);
                    res?;
                }
            }
        }
    }
    Ok(atoms::ok())
}

// A cache of compact ECC key to full PublicKey
static PK_CACHE: Lazy<Mutex<AdaptiveCache<HBin, PublicKey>>> =
    Lazy::new(|| Mutex::new(AdaptiveCache::new(1024).unwrap()));

mod atoms {
    rustler::atoms! {
        ok,
    }
}

rustler::init!("libp2p_crypto_nif", [verify_1]);
