use {
    ed25519_dalek::{Signature, SIGNATURE_LENGTH},
    noah::{
        errors::NoahError,
        keys::{Signature as NoahXfrSignature, SIGNATURE_LENGTH as NOAH_SIGNATURE_LENGTH},
    },
    noah_algebra::{prelude::*, serialization::NoahFromToBytes},
    serde::Serializer,
    ruc::*,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XfrSignature(pub Signature);

serialize_deserialize!(XfrSignature);

impl XfrSignature {
    /// Convert into bytes.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }

    /// Convert from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Signature::from_bytes(&bytes[0..SIGNATURE_LENGTH])
            .map(|sign| XfrSignature(sign))
            .c(d!(NoahError::DeserializationError))
    }

    pub fn into_noah(&self) -> Result<NoahXfrSignature> {
        NoahXfrSignature::noah_from_bytes(&self.to_bytes()).map_err(|e| eg!(e))
    }

    pub fn from_noah(value: &NoahXfrSignature) -> Result<Self> {
        let bytes = value.noah_to_bytes();
        XfrSignature::from_bytes(&bytes[1..NOAH_SIGNATURE_LENGTH - 1])
    }
}

impl NoahFromToBytes for XfrSignature {
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<Self, AlgebraError> {
        match XfrSignature::from_bytes(bytes) {
            Ok(x) => {Ok(x)}
            Err(_) => {Err(AlgebraError::DeserializationError)}
        }
    }
}
