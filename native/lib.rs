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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_compact_key() {
        // 1> Msg = <<"hello">>.
        let msg = b"hello";
        // 2> #{secret := PrivKey, public := {ecc_compact, {{'ECPoint', PubKeyBin}, _}}} = libp2p_crypto:generate_keys(ecc_compact).
        let compact_pubkey: &[u8] = &[
            4, 71, 122, 47, 159, 239, 56, 14, 15, 110, 163, 39, 114, 63, 206, 67, 52, 211, 122,
            143, 207, 141, 107, 52, 92, 132, 148, 77, 210, 136, 176, 183, 0, 81, 3, 39, 146, 241,
            54, 161, 169, 51, 165, 236, 43, 35, 159, 3, 120, 247, 87, 67, 132, 34, 183, 84, 30,
            238, 85, 71, 181, 50, 33, 16, 74,
        ];
        // 3> SignFun = libp2p_crypto:mk_sig_fun(PrivKey), SignFun(Msg).
        let signature: &[u8] = &[
            48, 69, 2, 33, 0, 153, 148, 48, 83, 186, 6, 68, 105, 233, 184, 140, 113, 79, 6, 56, 23,
            183, 18, 68, 176, 249, 122, 44, 247, 181, 94, 79, 71, 126, 95, 153, 16, 2, 32, 33, 128,
            70, 13, 156, 228, 216, 80, 111, 107, 154, 217, 66, 205, 129, 201, 48, 166, 127, 83, 26,
            246, 6, 88, 242, 135, 16, 108, 211, 148, 145, 46,
        ];
        let pk = PublicKey::try_from(&compact_pubkey[..]).unwrap();
        let verified = pk.verify(msg, &signature).is_ok();
        assert!(verified);
    }
}
