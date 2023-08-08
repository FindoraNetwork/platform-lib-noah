use {
    crate::publickey::XfrPublicKey,
    noah::xfr::{
        asset_record::AssetRecordType,
        structs::BlindAssetRecord as NoahBlindAssetRecord,
        structs::{XfrAmount, XfrAssetType},
    },
    ruc::*,
    serde::{Deserialize, Serialize},
};
/// A transfer input or output record as seen in the ledger
/// Amount and asset type can be confidential or non confidential
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlindAssetRecord {
    pub amount: XfrAmount,        // Amount being transferred
    pub asset_type: XfrAssetType, // Asset type being transferred
    pub public_key: XfrPublicKey, // ownership address
}

impl BlindAssetRecord {
    pub fn get_record_type(&self) -> AssetRecordType {
        AssetRecordType::from_flags(
            matches!(self.amount, XfrAmount::Confidential(_)),
            matches!(self.asset_type, XfrAssetType::Confidential(_)),
        )
    }

    pub fn is_public(&self) -> bool {
        matches!(
            self.get_record_type(),
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType
        )
    }
    pub fn into_noah(&self) -> Result<NoahBlindAssetRecord> {
        Ok(NoahBlindAssetRecord {
            amount: self.amount.clone(),
            asset_type: self.asset_type.clone(),
            public_key: self.public_key.into_noah()?,
        })
    }

    pub fn from_noah(value: &NoahBlindAssetRecord) -> Result<Self> {
        Ok(Self {
            amount: value.amount.clone(),
            asset_type: value.asset_type.clone(),
            public_key: XfrPublicKey::from_noah(&value.public_key)?,
        })
    }
}
