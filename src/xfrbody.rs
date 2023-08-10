use {
    crate::{BlindAssetRecord, OwnerMemo},
    noah::xfr::structs::{TracerMemo, XfrBody as NoahXfrBody, XfrProofs},
    noah_algebra::prelude::*,
    serde::{Deserialize, Serialize},
};
/// A confidential transfer body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct XfrBody {
    /// The list of input (blind) asset records.
    pub inputs: Vec<BlindAssetRecord>,
    /// The list of output (blind) asset records.
    pub outputs: Vec<BlindAssetRecord>,
    /// The list of proofs.
    pub proofs: XfrProofs,
    /// The memos for access tracers.
    pub asset_tracing_memos: Vec<Vec<TracerMemo>>, // each input or output can have a set of tracing memos
    /// The memos for the recipients.
    pub owners_memos: Vec<Option<OwnerMemo>>, // If confidential amount or asset type, lock the amount and/or asset type to the public key in asset_record
}
impl XfrBody {
    pub fn into_noah(&self) -> NoahXfrBody {
        NoahXfrBody {
            inputs: self
                .inputs
                .iter()
                .map(|it| it.into_noah())
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|it| it.into_noah())
                .collect(),
            proofs: self.proofs.clone(),
            asset_tracing_memos: self.asset_tracing_memos.clone(),
            owners_memos: self
                .owners_memos
                .iter()
                .map(|it| it.clone().map(|om| om.into_noah()))
                .collect(),
        }
    }

    pub fn from_noah(value: &NoahXfrBody) -> Self {
        Self {
            inputs: value
                .inputs
                .iter()
                .map(|it| BlindAssetRecord::from_noah(it))
                .collect(),
            outputs: value
                .outputs
                .iter()
                .map(|it| BlindAssetRecord::from_noah(it))
                .collect(),
            proofs: value.proofs.clone(),
            asset_tracing_memos: value.asset_tracing_memos.clone(),
            owners_memos: value
                .owners_memos
                .iter()
                .map(|it| it.clone().map(|om| OwnerMemo::from_noah(&om).unwrap()))
                .collect(),
        }
    }
}
