mod droptimer;
use helium_crypto::{ecc_compact::PublicKey, Verify};
use rustler::{Atom, Binary, Error as NifError, ListIterator, NifResult};
use std::convert::TryFrom;

mod atoms {
    rustler::atoms! {
        ok,
    }
}

// -spec verify(
//     Batch :: [{Bin :: binary(), [{Signature :: binary(), CompactEccKey :: binary()}, ...]}]
// ) -> ok | {error, Reason :: binary()}.
#[rustler::nif(name = "verify", schedule = "DirtyCpu")]
fn verify_1(batch: ListIterator) -> NifResult<Atom> {
    // let _timer = droptimer::DropTimer::new();
    for sub_batch in batch.map(|term| term.decode::<(Binary, ListIterator)>()) {
        let (msg, list) = sub_batch?;
        for pair in list.map(|term| term.decode::<(Binary, Binary)>()) {
            let (signature, compact_key) = pair?;
            let pk = PublicKey::try_from(compact_key.as_slice())
                .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?;
            pk.verify(msg.as_slice(), signature.as_slice())
                .map_err(|e| NifError::Term(Box::new(format!("{}", e))))?
        }
    }
    Ok(atoms::ok())
}

rustler::init!("libp2p_crypto_nif", [verify_1]);
