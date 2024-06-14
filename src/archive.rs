use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::error::Error;

/// The archive that describes the single file storaing all information.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct Archive {
    /// Archive version.
    pub version: String,
    /// Automatically generated unique ID of this archive.
    pub uid: String,
    /// Process ID.
    pub pid: String,

    /// Archive data.
    pub data: String,
}

/// The archive data.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ArchiveData {
    /// The actual share of the secret.
    pub share: Share,
    /// Share information.
    pub info: ShareInfo,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Checksum {
    /// Sha-512
    Sha512(String),
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ShareInfo {
    /// Some plain text comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Some information about the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretInfo>,
}

// Describing an individual share.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Share {
    Plain(DataRepresentation, Checksum),
    Encrypted { pass_hash: Hash, data: DataRepresentation, checksum: Checksum },
}

// Describing an individual share.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DataRepresentation {
    Plain(String),
    Base64(String),
}

impl DataRepresentation {
    pub fn base64(v: Vec<u8>) -> Self {
        Self::Base64(STANDARD.encode(v))
    }

    pub fn decode(&self) -> Result<String> {
        match self {
            | DataRepresentation::Plain(v) => Ok(v.clone()),
            | DataRepresentation::Base64(v) => match STANDARD.decode(v) {
                | Ok(v) => Ok(String::from_utf8(v).unwrap()),
                | Err(_) => Err(Error::Decoding("base64".to_owned()).into()),
            }
        }
    }
}

/// Describes the hash algorithm and value that is used for password
/// verification.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Hash {
    /// Argon2id hash.
    Argon2id(String),
}

/// Describes the secret that has been sharded. Contains information about
/// how to restore.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SecretInfo {
    /// The amount of shares that were generated for the secret.
    pub num_shares: usize,
    /// The amount of shares that are needed for restoring the secret.
    pub threshold: usize,
}
