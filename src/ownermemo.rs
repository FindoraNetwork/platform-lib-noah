use {
    noah::{
        keys::KeyType, ristretto::CompressedEdwardsY, xfr::structs::OwnerMemo as NoahOwnerMemo,
        NoahError,
    },
    noah_algebra::{prelude::*, serialization::NoahFromToBytes},
    noah_crypto::hybrid_encryption::XPublicKey,
    serde::{Deserialize, Serialize},
};

const SECP_KEY_IDENTIFIER: &str = "secp";

/// Information directed to secret key holder of a BlindAssetRecord
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerMemo {
    pub blind_share: BlindShare,
    pub lock: ZeiHybridCipher,
}

#[derive(Clone, Deserialize, Serialize, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum BlindShare {
    CompressedEdwardsY(CompressedEdwardsY),
    BlindShareData(String, CompactByteArray),
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

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self, AlgebraError> {
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
        let lock_bytes = self.lock.noah_to_bytes();

        match self.blind_share.clone() {
            BlindShare::CompressedEdwardsY(bs) => NoahOwnerMemo {
                key_type: KeyType::Ed25519,
                blind_share_bytes: CompactByteArray(bs.noah_to_bytes()),
                lock_bytes: CompactByteArray(lock_bytes),
            },
            BlindShare::BlindShareData(_, v) => NoahOwnerMemo {
                key_type: KeyType::Secp256k1,
                blind_share_bytes: CompactByteArray(v.0),
                lock_bytes: CompactByteArray(lock_bytes),
            },
        }
    }

    pub fn from_noah(value: &NoahOwnerMemo) -> Result<Self, NoahError> {
        match value.key_type {
            KeyType::Ed25519 => Ok(Self {
                blind_share: BlindShare::CompressedEdwardsY(CompressedEdwardsY::from_slice(
                    value.blind_share_bytes.0.as_slice(),
                )),
                lock: ZeiHybridCipher::noah_from_bytes(&value.lock_bytes.0)?,
            }),
            KeyType::Secp256k1 => Ok(Self {
                blind_share: BlindShare::BlindShareData(
                    String::from(SECP_KEY_IDENTIFIER),
                    value.blind_share_bytes.clone(),
                ),
                lock: ZeiHybridCipher::noah_from_bytes(&value.lock_bytes.0)?,
            }),
            KeyType::EthAddress => Err(NoahError::ParameterError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::XfrKeyPair;
    use base64::Engine;
    use noah::ristretto::CompressedEdwardsY;
    use noah::xfr::structs::AssetType;
    use rand_chacha::ChaChaRng;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct OldOwnerMemo {
        pub blind_share: CompressedEdwardsY,
        pub lock: ZeiHybridCipher,
    }

    #[test]
    pub fn test_old_owner_memo_compatibility() {
        let mut prng = ChaChaRng::seed_from_u64(2987534u64);
        let ed_kp = XfrKeyPair::generate(&mut prng);
        let ed_pk = ed_kp.get_pk();
        let at = AssetType::from_identical_byte(7u8);
        {
            let (nom, _) = NoahOwnerMemo::from_amount(&mut prng, 12345u64, &ed_pk.0).unwrap();
            let oom = OldOwnerMemo {
                blind_share: CompressedEdwardsY::from_slice(nom.blind_share_bytes.0.as_slice()),
                lock: ZeiHybridCipher::noah_from_bytes(nom.lock_bytes.0.as_slice()).unwrap(),
            };

            let oom_bytes = serde_json::to_string(&oom).unwrap();

            let new_om: OwnerMemo = serde_json::from_str(oom_bytes.as_str()).unwrap();
            assert_eq!(nom, new_om.into_noah());
        }
        {
            let (nom, _) = NoahOwnerMemo::from_asset_type(&mut prng, &at, &ed_pk.0).unwrap();
            let oom = OldOwnerMemo {
                blind_share: CompressedEdwardsY::from_slice(nom.blind_share_bytes.0.as_slice()),
                lock: ZeiHybridCipher::noah_from_bytes(nom.lock_bytes.0.as_slice()).unwrap(),
            };

            let oom_bytes = serde_json::to_string(&oom).unwrap();

            let new_om: OwnerMemo = serde_json::from_str(oom_bytes.as_str()).unwrap();
            assert_eq!(nom, new_om.into_noah());
        }
        {
            let (nom, _, _) =
                NoahOwnerMemo::from_amount_and_asset_type(&mut prng, 983456u64, &at, &ed_pk.0)
                    .unwrap();
            let oom = OldOwnerMemo {
                blind_share: CompressedEdwardsY::from_slice(nom.blind_share_bytes.0.as_slice()),
                lock: ZeiHybridCipher::noah_from_bytes(nom.lock_bytes.0.as_slice()).unwrap(),
            };

            let oom_bytes = serde_json::to_string(&oom).unwrap();

            let new_om: OwnerMemo = serde_json::from_str(oom_bytes.as_str()).unwrap();
            assert_eq!(nom, new_om.into_noah());
        }
    }

    #[test]
    pub fn test_owner_memo_ed25519() {
        let mut prng = ChaChaRng::seed_from_u64(2987534u64);
        let ed_kp = XfrKeyPair::generate(&mut prng);
        let ed_pk = ed_kp.get_pk();
        let at = AssetType::from_identical_byte(7u8);

        {
            let (nom, _) = NoahOwnerMemo::from_amount(&mut prng, 12345u64, &ed_pk.0).unwrap();
            let om = OwnerMemo::from_noah(&nom).unwrap();
            let om_bytes = serde_json::to_vec(&om).unwrap();

            let new_om: OwnerMemo = serde_json::from_slice(om_bytes.as_slice()).unwrap();

            assert_eq!(nom, new_om.into_noah())
        }
        {
            let (nom, _) = NoahOwnerMemo::from_asset_type(&mut prng, &at, &ed_pk.0).unwrap();
            let om = OwnerMemo::from_noah(&nom).unwrap();
            let om_bytes = serde_json::to_vec(&om).unwrap();

            let new_om: OwnerMemo = serde_json::from_slice(om_bytes.as_slice()).unwrap();

            assert_eq!(nom, new_om.into_noah())
        }
        {
            let (nom, _, _) =
                NoahOwnerMemo::from_amount_and_asset_type(&mut prng, 12345u64, &at, &ed_pk.0)
                    .unwrap();
            let om = OwnerMemo::from_noah(&nom).unwrap();
            let om_bytes = serde_json::to_vec(&om).unwrap();

            let new_om: OwnerMemo = serde_json::from_slice(om_bytes.as_slice()).unwrap();

            assert_eq!(nom, new_om.into_noah())
        }
    }

    #[test]
    pub fn test_owner_memo_secp256k1() {
        let mut prng = ChaChaRng::seed_from_u64(2987534u64);
        let ed_kp = XfrKeyPair::generate_secp256k1(&mut prng);
        let ed_pk = ed_kp.get_pk();
        let at = AssetType::from_identical_byte(7u8);

        {
            let (nom, _) = NoahOwnerMemo::from_amount(&mut prng, 12345u64, &ed_pk.0).unwrap();
            let om = OwnerMemo::from_noah(&nom).unwrap();
            let om_bytes = serde_json::to_vec(&om).unwrap();

            let new_om: OwnerMemo = serde_json::from_slice(om_bytes.as_slice()).unwrap();
            assert_eq!(nom, new_om.into_noah())
        }
        {
            let (nom, _) = NoahOwnerMemo::from_asset_type(&mut prng, &at, &ed_pk.0).unwrap();
            let om = OwnerMemo::from_noah(&nom).unwrap();
            let om_bytes = serde_json::to_vec(&om).unwrap();

            let new_om: OwnerMemo = serde_json::from_slice(om_bytes.as_slice()).unwrap();

            assert_eq!(nom, new_om.into_noah())
        }
        {
            let (nom, _, _) =
                NoahOwnerMemo::from_amount_and_asset_type(&mut prng, 12345u64, &at, &ed_pk.0)
                    .unwrap();
            let om = OwnerMemo::from_noah(&nom).unwrap();
            let om_bytes = serde_json::to_vec(&om).unwrap();

            let new_om: OwnerMemo = serde_json::from_slice(om_bytes.as_slice()).unwrap();

            assert_eq!(nom, new_om.into_noah())
        }
    }

    #[test]
    pub fn test_old_owner_memo() {
        let om_str = r#"{
                  "blind_share": "baw3L2a-HwfvrCjjwuh6xymwsswzZ0cjsBnsBfjMlvU=",
                  "lock": {
                    "ciphertext": "p8gk4Dt5AdGIy1ZVUSf8LOmzSGAgI8tTV_YImUr53wxqJ3X3vlIkMw==",
                    "ephemeral_public_key": "d2QzbADM1wKuOqtUosI0yR75yYt2eU9MgfKnGCO3eS8="
                  }
                }"#;

        let bs: Vec<u8> = base64::engine::general_purpose::URL_SAFE
            .decode("baw3L2a-HwfvrCjjwuh6xymwsswzZ0cjsBnsBfjMlvU=")
            .unwrap();

        let om: OwnerMemo = serde_json::from_str(om_str).unwrap();

        assert_eq!(
            om.blind_share,
            BlindShare::CompressedEdwardsY(CompressedEdwardsY::noah_from_bytes(&bs).unwrap())
        );
    }
}
