use {
    noah::ristretto::CompressedEdwardsY,
    noah::{keys::KeyType, xfr::structs::OwnerMemo as NoahOwnerMemo},
    noah_algebra::{prelude::*, serialization::NoahFromToBytes},
    noah_crypto::hybrid_encryption::{XPublicKey},
    ruc::*,
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
    pub(crate) ciphertext: CompactByteArray,
    pub(crate) ephemeral_public_key: XPublicKey,
}
impl NoahFromToBytes for ZeiHybridCipher {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.ephemeral_public_key.noah_to_bytes());
        bytes.append(&mut self.ciphertext.noah_to_bytes());
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> core::result::Result<Self, AlgebraError> {
        if bytes.len() < 32 {
            Err(AlgebraError::DeserializationError)
        } else {
            let ephemeral_public_key = XPublicKey::noah_from_bytes(&bytes[0..32])?;
            let ciphertext = CompactByteArray::noah_from_bytes(&bytes[32..])?;
            Ok(Self {
                ciphertext,
                ephemeral_public_key,
            })
        }
    }
}
impl OwnerMemo {
    pub fn into_noah(&self) -> NoahOwnerMemo {
        NoahOwnerMemo {
            key_type: KeyType::Ed25519,
            blind_share_bytes: CompactByteArray(self.blind_share.to_bytes().to_vec()),
            lock_bytes: CompactByteArray(self.lock.noah_to_bytes()),
        }
    }

    pub fn from_noah(value: &NoahOwnerMemo) -> Result<Self> {
        Ok(Self {
            blind_share: CompressedEdwardsY::from_slice(&value.blind_share_bytes.0),
            lock: ZeiHybridCipher::noah_from_bytes(&value.lock_bytes.0).c(d!())?,
        })
    }
}
