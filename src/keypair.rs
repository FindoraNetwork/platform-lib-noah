use {
    crate::{publickey::XfrPublicKey, secretkey::XfrSecretKey, signature::XfrSignature},
    ed25519_dalek::{PublicKey, SecretKey},
    noah::keys::KeyPair as NoahXfrKeyPair,
    noah_algebra::prelude::*,
    ruc::*,
    serde::{Deserialize, Serialize},
    wasm_bindgen::prelude::*,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct XfrKeyPair {
    pub pub_key: XfrPublicKey,
    pub(crate) sec_key: XfrSecretKey,
}
impl XfrKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let kp = ed25519_dalek::Keypair::generate(prng);
        XfrKeyPair {
            pub_key: XfrPublicKey(kp.public),
            sec_key: XfrSecretKey(kp.secret_key()),
        }
    }

    pub fn into_noah(&self) -> Result<NoahXfrKeyPair> {
        self.sec_key.clone().into_noah().map(|sk| sk.into_keypair())
    }

    pub fn from_noah(value: &NoahXfrKeyPair) -> Result<Self> {
        XfrSecretKey::from_noah(value.get_sk_ref()).map(|sk| sk.into_keypair())
    }

    pub fn sign(&self, msg: &[u8]) -> Result<XfrSignature> {
        self.sec_key.sign(msg)
    }

    #[inline(always)]
    pub fn get_pk(&self) -> XfrPublicKey {
        self.pub_key
    }

    #[inline(always)]
    pub fn get_pk_ref(&self) -> &XfrPublicKey {
        &self.pub_key
    }

    #[inline(always)]
    pub fn get_sk(&self) -> XfrSecretKey {
        self.sec_key.clone()
    }

    #[inline(always)]
    pub fn get_sk_ref(&self) -> &XfrSecretKey {
        &self.sec_key
    }
}
impl NoahFromToBytes for XfrKeyPair {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(self.sec_key.noah_to_bytes().as_slice());
        vec.extend_from_slice(self.pub_key.noah_to_bytes().as_slice());
        vec
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<Self, AlgebraError> {
        if bytes.len() == 64 {
            let sk = match SecretKey::from_bytes(&bytes[0..32]) {
                Ok(a) => {Ok(a)}
                Err(_) => {Err(AlgebraError::DeserializationError)}
            }?;
            let pk = match PublicKey::from_bytes(&bytes[32..64]) {
                Ok(a) => {Ok(a)}
                Err(_) => {Err(AlgebraError::DeserializationError)}
            }?;
            Ok(XfrKeyPair {
                sec_key: XfrSecretKey(
                    sk,
                ),
                pub_key: XfrPublicKey(
                    pk,
                ),
            })
        } else {
            Err(AlgebraError::DeserializationError)
        }
    }
}
