use {
    crate::{signature::XfrSignature, XfrKeyPair, XfrPublicKey},
    ed25519_dalek::{PublicKey, SecretKey, SECRET_KEY_LENGTH},
    noah::{
        errors::NoahError,
        keys::{SecretKey as NoahXfrSecretKey, Signature as NoahXfrSignature},
    },
    noah_algebra::{
        cmp::Ordering,
        hash::{Hash, Hasher},
        prelude::*,
        serialization::NoahFromToBytes,
    },
    ruc::*,
    serde::Serializer,
};

#[derive(Debug)]
pub struct XfrSecretKey(pub(crate) SecretKey);

impl XfrSecretKey {
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        *self.0.as_bytes()
    }

    /// Convert from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        SecretKey::from_bytes(&bytes[0..SECRET_KEY_LENGTH])
            .map(|pk| XfrSecretKey(pk))
            .c(d!(NoahError::DeserializationError))
    }
    pub fn sign(&self, message: &[u8]) -> Result<XfrSignature> {
        let sk: NoahXfrSecretKey = self.clone().into_noah().c(d!())?;
        sk.sign(message).c(d!()).and_then(|sign| {
            if let NoahXfrSignature::Ed25519(v) = sign {
                Ok(XfrSignature(v))
            } else {
                Err(NoahError::SignatureError).c(d!())
            }
        })
    }
    pub fn into_keypair(&self) -> XfrKeyPair {
        XfrKeyPair {
            pub_key: XfrPublicKey(PublicKey::from(&self.0)),
            sec_key: self.clone(),
        }
    }
    pub fn into_noah(&self) -> Result<NoahXfrSecretKey> {
        NoahXfrSecretKey::noah_from_bytes(&self.to_bytes()).map_err(|e| eg!(e))
    }

    pub fn from_noah(value: &NoahXfrSecretKey) -> Result<Self> {
        if let NoahXfrSecretKey::Ed25519(v) = value {
            Ok(Self(
                SecretKey::from_bytes(&v.to_bytes()).map_err(|e| eg!(e))?,
            ))
        } else {
            Err(eg!("type error"))
        }
    }
}

impl NoahFromToBytes for XfrSecretKey {
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

impl Clone for XfrSecretKey {
    fn clone(&self) -> Self {
        XfrSecretKey(SecretKey::from_bytes(self.0.as_ref()).unwrap())
    }
}

impl Eq for XfrSecretKey {}

impl PartialEq for XfrSecretKey {
    fn eq(&self, other: &XfrSecretKey) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Ord for XfrSecretKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for XfrSecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for XfrSecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

serialize_deserialize!(XfrSecretKey);
