use rustler::{Binary, OwnedBinary};
use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
};

pub struct HBin(OwnedBinary);

impl HBin {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<'a> From<&Binary<'a>> for HBin {
    fn from(other: &Binary<'a>) -> Self {
        HBin(other.to_owned().expect("OOM"))
    }
}

impl Borrow<[u8]> for HBin {
    fn borrow(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Hash for HBin {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.as_slice().hash(hasher);
    }
}

impl PartialEq for HBin {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for HBin {}
