use {
    crate::{publickey::XfrPublicKey, secretkey::XfrSecretKey, signature::XfrSignature},
    noah::keys::KeyPair as NoahXfrKeyPair,
    noah_algebra::prelude::*,
    serde::{Deserialize, Serialize},
    wasm_bindgen::prelude::*,
};
use noah::parameters::AddressFormat::{ED25519, SECP256K1};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct XfrKeyPair {
    pub pub_key: XfrPublicKey,
    pub(crate) sec_key: XfrSecretKey,
}
impl XfrKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let kp = NoahXfrKeyPair::sample(prng, ED25519);
        XfrKeyPair {
            pub_key: XfrPublicKey(kp.get_pk()),
            sec_key: XfrSecretKey(kp.get_sk()),
        }
    }

    pub fn generate_secp256k1<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let kp = NoahXfrKeyPair::sample(prng, SECP256K1);
        XfrKeyPair {
            pub_key: XfrPublicKey(kp.get_pk()),
            sec_key: XfrSecretKey(kp.get_sk()),
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

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        let nkp = NoahXfrKeyPair::noah_from_bytes(bytes)?;
        Ok(Self{
            pub_key: XfrPublicKey(nkp.get_pk()),
            sec_key: XfrSecretKey(nkp.get_sk())
        })
    }
}
