use {
    noah::{
        keys::{Signature as NoahXfrSignature},
    },
    noah_algebra::{prelude::*, serialization::NoahFromToBytes},
    serde::Serializer,
};
use noah::keys::KeyType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XfrSignature(pub NoahXfrSignature);

serialize_deserialize!(XfrSignature);

impl XfrSignature {

    pub fn into_noah(&self) -> Result<NoahXfrSignature> {
        Ok(self.0.clone())
    }

    pub fn from_noah(value: &NoahXfrSignature) -> Result<Self> {
        Ok(Self(value.clone()))
    }
}

impl NoahFromToBytes for XfrSignature {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.noah_to_bytes();
        let typ = bytes[0];
        if KeyType::from_byte(typ) == KeyType::Ed25519 {
            bytes[1..65].to_vec()
        } else {
            bytes
        }
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(NoahXfrSignature::noah_from_bytes(bytes)?))
    }
}
