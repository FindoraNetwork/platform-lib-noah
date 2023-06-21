use {
    crate::signature::XfrSignature,
    noah::keys::PublicKey as NoahXfrPublicKey,
    noah_algebra::{
        hash::{Hash, Hasher},
        prelude::*,
        serialization::NoahFromToBytes,
    },
    serde::Serializer,
    wasm_bindgen::prelude::*,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Default)]
#[wasm_bindgen]
pub struct XfrPublicKey(pub(crate) NoahXfrPublicKey);

serialize_deserialize!(XfrPublicKey);

impl XfrPublicKey {

    pub fn verify(&self, message: &[u8], signature: &XfrSignature) -> Result<()> {
        self.0.verify(message, &signature.into_noah()?)
    }

    pub fn into_noah(&self) -> Result<NoahXfrPublicKey> {
        Ok(self.0)
    }

    pub fn from_noah(value: &NoahXfrPublicKey) -> Result<Self> {
        Ok(Self(value.clone()))
    }
}

impl NoahFromToBytes for XfrPublicKey {
    // Ed25519 public keys serialize to 32 byte format so don't need additional logic
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.0.noah_to_bytes()
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(NoahXfrPublicKey::noah_from_bytes(bytes)?))
    }
}

impl Hash for XfrPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.noah_to_bytes().hash(state)
    }
}

#[cfg(test)]
mod tests {
    use crate::noah_algebra::prelude::SeedableRng;
    use crate::noah_algebra::serialization::NoahFromToBytes;
    use crate::{XfrKeyPair, XfrPublicKey};
    use rand_chacha::ChaChaRng;

    #[test]
    pub fn test_old_public_key_compatibility() {
        let mut prng = ChaChaRng::seed_from_u64(2342935u64);
        let kp = ed25519_dalek::Keypair::generate(&mut prng);
        let pk = kp.public_key();

        let xpk = XfrPublicKey::noah_from_bytes(&pk.to_bytes()).unwrap();

        assert_eq!(pk.to_bytes(), xpk.noah_to_bytes().as_slice());
        assert_eq!(xpk.noah_to_bytes().len(), 32)
    }

    #[test]
    pub fn test_new_pk() {
        let mut prng = ChaChaRng::seed_from_u64(2987534u64);
        let ed_kp = XfrKeyPair::generate(&mut prng);
        let ed_pk = ed_kp.get_pk();

        assert_eq!(ed_pk.noah_to_bytes().len(), 32);

        let ed_sp = XfrKeyPair::generate_secp256k1(&mut prng);
        let ed_sp = ed_sp.get_pk();

        assert_eq!(ed_sp.noah_to_bytes().len(), 34);
    }
}
