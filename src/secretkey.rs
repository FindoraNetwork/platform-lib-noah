use {
    crate::{signature::XfrSignature, XfrKeyPair, XfrPublicKey},
    ed25519_dalek::{SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH},
    noah::{
        keys::{SecretKey as NoahXfrSecretKey, KeyType},
    },
    noah_algebra::{
        hash::{Hash, Hasher},
        prelude::*,
        serialization::NoahFromToBytes,
    },
    serde::Serializer,
};
use noah::keys::KeyType::Ed25519;

#[derive(Debug, Clone, Eq, PartialOrd, PartialEq, Ord)]
pub struct XfrSecretKey(pub(crate) NoahXfrSecretKey);

impl XfrSecretKey {

    pub fn sign(&self, message: &[u8]) -> Result<XfrSignature> {
        let sig = self.0.sign(message)?;
        Ok(XfrSignature::from_noah(&sig)?)
    }
    pub fn into_keypair(&self) -> XfrKeyPair {
        let nkp = self.0.clone().into_keypair();
        XfrKeyPair{
            pub_key: XfrPublicKey(nkp.get_pk()),
            sec_key: XfrSecretKey(nkp.get_sk())
        }
    }
    pub fn into_noah(&self) -> Result<NoahXfrSecretKey> {
        Ok(self.0.clone())
    }

    pub fn from_noah(value: &NoahXfrSecretKey) -> Result<Self> {
        Ok(Self(value.clone()))
    }
}

impl NoahFromToBytes for XfrSecretKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.noah_to_bytes();
        let typ = KeyType::from_byte(bytes[0]);
        if typ == Ed25519 {
            bytes[1..ED25519_SECRET_KEY_LENGTH+1].to_vec()
        } else {
            bytes
        }
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(NoahXfrSecretKey::noah_from_bytes(bytes)?))
    }
}

impl Hash for XfrSecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.noah_to_bytes().hash(state)
    }
}

serialize_deserialize!(XfrSecretKey);
