use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::error::Error;

pub fn split_version_and_data(data: &Vec<u8>) -> Result<(String, &[u8])> {
    assert_eq!(data[0], b'#');
    assert_eq!(data[1], b'v');
    let mut version = String::new();
    let mut i = 2;
    while data[i] != b'#' {
        version.push(data[i] as char);
        i += 1;
    }
    Ok((version, &data[i+1..]))
}

/// The archive that describes the single file storaing all information.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct Archive {
    /// Automatically generated unique ID of this archive.
    pub uid: String,
    /// The actual share of the secret.
    pub share: Share,

    /// Share information
    pub info: ArchiveInfo,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ArchiveInfo {
    /// This shares name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    /// Plain base64 encoded share data.
    Plain(DataRepresentation),
    /// Symmetrically encrypted, base64 encoded share data.
    Encrypted { hash: Hash, data: DataRepresentation },
}

// Describing an individual share.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DataRepresentation {
    /// Plain base64 encoded share data.
    Plain(String),
    /// Symmetrically encrypted, base64 encoded share data.
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
