mod droptimer;

use helium_crypto::{ecc_compact, ed25519, KeyType, Verify};
use rayon::prelude::*;
use rustler::{Atom, Binary, Error as NifError, ListIterator, NifResult, Term};
use std::convert::TryFrom;

// -spec verify(
//     [{Bin :: binary(), [{Signature :: binary(), PubKeyBin :: libp2p_crypto:pubkey_bin()}, ...]}]
// ) -> ok | {error, Reason :: binary()}.
#[rustler::nif(name = "verify", schedule = "DirtyCpu")]
fn verify_1(batch: ListIterator) -> NifResult<Atom> {
    // let _timer = droptimer::DropTimer::new();
    for sub_batch in batch.map(|term| term.decode::<(Binary, Vec<Term>)>()) {
        let (msg, list) = sub_batch?;
        let msg = msg.as_slice();
        list.into_par_iter()
            .try_for_each(|pair| verify_one(msg, pair))
            .map_err(|e| NifError::Term(Box::new(e)))?;
    }

    Ok(atoms::ok())
}

fn verify_one(msg: &[u8], term: Term) -> Result<(), String> {
    let (signature, pubkey_bin) = term
        .decode::<(Binary, Binary)>()
        .map_err(|_| "decode".to_owned())?;
    let key_type: KeyType = pubkey_bin
        .first()
        .ok_or_else(|| "empty".to_owned())
        .and_then(|&b| KeyType::try_from(b).map_err(|e| e.to_string()))?;
    match key_type {
        KeyType::EccCompact => {
            let pk = ecc_compact::PublicKey::try_from(pubkey_bin.as_slice())
                .map_err(|e| e.to_string())?;
            pk.verify(msg, signature.as_slice())
                .map_err(|e| e.to_string())?
        }
        KeyType::Ed25519 => {
            let pk =
                ed25519::PublicKey::try_from(pubkey_bin.as_slice()).map_err(|e| e.to_string())?;
            pk.verify(msg, signature.as_slice())
                .map_err(|e| e.to_string())?
        }
    }
    Ok(())
}

mod atoms {
    rustler::atoms! {
       ok,
    }
}

rustler::init!("libp2p_crypto_nif", [verify_1]);
