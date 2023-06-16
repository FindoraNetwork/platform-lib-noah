use {
    noah::ristretto::CompressedEdwardsY,
    noah::{keys::KeyType, xfr::structs::OwnerMemo as NoahOwnerMemo},
    noah_algebra::{prelude::*, serialization::NoahFromToBytes},
    noah_crypto::basic::hybrid_encryption::{Ctext, XPublicKey},
    serde::{Deserialize, Serialize},
};
/// Information directed to secret key holder of a BlindAssetRecord
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerMemo {
    pub blind_share: CompressedEdwardsY,
    pub lock: ZeiHybridCipher,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct ZeiHybridCipher {
    pub(crate) ciphertext: Ctext,
    pub(crate) ephemeral_public_key: XPublicKey,
}
impl NoahFromToBytes for ZeiHybridCipher {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.ephemeral_public_key.noah_to_bytes());
        bytes.append(&mut self.ciphertext.noah_to_bytes());
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            Err(eg!(NoahError::DeserializationError))
        } else {
            let ephemeral_public_key = XPublicKey::noah_from_bytes(&bytes[0..32])?;
            let ciphertext = Ctext::noah_from_bytes(&bytes[32..])?;
            Ok(Self {
                ciphertext,
                ephemeral_public_key,
            })
        }
    }
}
impl OwnerMemo {
    pub fn into_noah(&self) -> NoahOwnerMemo {

        let lock_bytes = self.lock.noah_to_bytes();

        if lock_bytes.len() == 72 ||
            lock_bytes.len() == 40 ||
            lock_bytes.len() == 64 {
            NoahOwnerMemo {
                key_type: KeyType::Ed25519,
                blind_share_bytes: self.blind_share.to_bytes().to_vec(),
                lock_bytes: lock_bytes,
            }
        } else if lock_bytes.len() == 89 ||
            lock_bytes.len() == 57 ||
            lock_bytes.len() == 81{
            NoahOwnerMemo {
                key_type: KeyType::Secp256k1,
                blind_share_bytes: self.blind_share.to_bytes().to_vec(),
                lock_bytes: lock_bytes,
            }
        } else {
            panic!("")
        }


    }

    pub fn from_noah(value: &NoahOwnerMemo) -> Result<Self> {
        Ok(Self {
            blind_share: CompressedEdwardsY::from_slice(&value.blind_share_bytes),
            lock: ZeiHybridCipher::noah_from_bytes(&value.lock_bytes)?,
        })
    }
}
