mod droptimer;

use helium_crypto::{ecc_compact, ed25519, KeyType, Verify};
use rustler::{Atom, Binary, Error as NifError, ListIterator, NifResult};
use std::convert::TryFrom;

// -spec verify(
//     [{Bin :: binary(), [{Signature :: binary(), PubKeyBin :: libp2p_crypto:pubkey_bin()}, ...]}]
// ) -> ok | {error, Reason :: binary()}.
#[rustler::nif(name = "verify", schedule = "DirtyCpu")]
fn verify_1(batch: ListIterator) -> NifResult<Atom> {
    // let _timer = droptimer::DropTimer::new();
    for sub_batch in batch.map(|term| term.decode::<(Binary, ListIterator)>()) {
        let (msg, list) = sub_batch?;
        for pair in list.map(|term| term.decode::<(Binary, Binary)>()) {
            let (signature, pubkey_bin) = pair?;
            let key_type: KeyType = pubkey_bin.first().ok_or(NifError::BadArg).and_then(|&b| {
                KeyType::try_from(b).map_err(|e| NifError::Term(Box::new(format!("{}", e))))
            })?;
            match key_type {
                KeyType::EccCompact => {
                    let pk = ecc_compact::PublicKey::try_from(pubkey_bin.as_slice())
                        .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?;
                    pk.verify(msg.as_slice(), signature.as_slice())
                        .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?
                }
                KeyType::Ed25519 => {
                    let pk = ed25519::PublicKey::try_from(pubkey_bin.as_slice())
                        .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?;
                    pk.verify(msg.as_slice(), signature.as_slice())
                        .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?
                }
            }
        }
    }
    Ok(atoms::ok())
}

mod atoms {
    rustler::atoms! {
        ok,
    }
}

rustler::init!("libp2p_crypto_nif", [verify_1]);
