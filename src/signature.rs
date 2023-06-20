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

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use super::*;
    use ed25519_dalek::Signer;
    use crate::XfrKeyPair;

    #[test]
    pub fn test_old_signature_compatibility() {
        let mut prng = ChaChaRng::seed_from_u64(2342935u64);

        // generate ed25519 KP by old method
        let old_kp = ed25519_dalek::Keypair::generate(&mut prng);

        let message = "some message";
        let old_sig = old_kp.sign(message.as_bytes());
        let old_sig_bytes = old_sig.to_bytes();

        let new_sig = XfrSignature::noah_from_bytes(&old_sig_bytes).unwrap();
        let new_sig_bytes = new_sig.noah_to_bytes();

        assert_eq!(new_sig_bytes.len(), 64);

        assert_eq!(
            old_sig_bytes,
            new_sig_bytes.as_slice()
        );
    }

    #[test]
    pub fn test_new_signatures() {
        let mut prng = ChaChaRng::seed_from_u64(82934759845u64);
        let msg = "some message to sign";

        let ed_kp = XfrKeyPair::generate(&mut prng);
        let ed_sign = ed_kp.sign(msg.as_bytes()).unwrap();
        let ed_sign_bytes = ed_sign.noah_to_bytes();

        assert!(ed_kp.get_pk_ref().verify(msg.as_bytes(), &ed_sign).is_ok());
        assert_eq!(ed_sign, XfrSignature::noah_from_bytes(ed_sign_bytes.as_slice()).unwrap());
        assert_eq!(ed_sign_bytes.len(), 64);

        let sp_kp = XfrKeyPair::generate_secp256k1(&mut prng);
        let sp_sign = sp_kp.sign(msg.as_bytes()).unwrap();
        let sp_sign_bytes = sp_sign.noah_to_bytes();

        assert!(sp_kp.get_pk_ref().verify(msg.as_bytes(), &sp_sign).is_ok());
        assert_eq!(sp_sign, XfrSignature::noah_from_bytes(sp_sign_bytes.as_slice()).unwrap());
        assert_eq!(sp_sign_bytes.len(), 66);
    }
}