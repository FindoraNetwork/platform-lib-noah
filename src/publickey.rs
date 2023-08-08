use {
    crate::signature::XfrSignature,
    ed25519_dalek::{PublicKey, PUBLIC_KEY_LENGTH},
    noah::keys::{PublicKey as NoahXfrPublicKey, PublicKeyInner},
    noah_algebra::{
        cmp::Ordering,
        hash::{Hash, Hasher},
        prelude::*,
        serialization::NoahFromToBytes,
    },
    ruc::*,
    serde::Serializer,
    wasm_bindgen::prelude::*,
};

#[derive(Clone, Copy, Debug, Default)]
#[wasm_bindgen]
pub struct XfrPublicKey(pub(crate) PublicKey);

serialize_deserialize!(XfrPublicKey);

impl XfrPublicKey {
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        *self.0.as_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        PublicKey::from_bytes(&bytes[0..PUBLIC_KEY_LENGTH])
            .map(|pk| XfrPublicKey(pk))
            .map_err(|e| eg!(e))
    }
    pub fn verify(&self, message: &[u8], signature: &XfrSignature) -> Result<()> {
        let pk: NoahXfrPublicKey = self.clone().into_noah()?;
        pk.verify(message, &signature.into_noah()?).c(d!())
    }

    pub fn into_noah(&self) -> Result<NoahXfrPublicKey> {
        NoahXfrPublicKey::noah_from_bytes(&self.to_bytes()).map_err(|e| eg!(e))
    }

    pub fn from_noah(value: &NoahXfrPublicKey) -> Result<Self> {
        if let PublicKeyInner::Ed25519(v) = value.inner() {
            Ok(Self(v.clone()))
        } else {
            Err(eg!("type error"))
        }
    }
}

impl NoahFromToBytes for XfrPublicKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<Self, AlgebraError> {
        match Self::from_bytes(bytes) {
            Ok(a) => {Ok(a)}
            Err(_) => {Err(AlgebraError::DeserializationError)}
        }
    }
}

impl Eq for XfrPublicKey {}

impl PartialEq for XfrPublicKey {
    fn eq(&self, other: &XfrPublicKey) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Ord for XfrPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for XfrPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for XfrPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}
