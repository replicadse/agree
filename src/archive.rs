use {
    crate::error::Error,
    anyhow::Result,
    base64::{
        engine::general_purpose::STANDARD,
        Engine,
    },
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Base64String(String);
impl Base64String {
    pub fn new<T: AsRef<[u8]>>(v: T) -> Self {
        Self(STANDARD.encode(v))
    }

    pub fn decode(&self) -> Result<Vec<u8>> {
        match STANDARD.decode(&self.0) {
            | Ok(v) => Ok(v),
            | Err(_) => Err(Error::Decoding("base64".to_owned()).into()),
        }
    }
}

/// The archive that describes the single file storaing all information.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct Archive {
    /// Archive version.
    pub version: String,
    /// Unique ID.
    pub uid: String,
    /// Process ID.
    pub pid: String,

    /// Archive data.
    pub data: Base64String,
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
    Plain {
        data: Base64String,
        checksum: Checksum,
    },
    Encrypted {
        pass_hash: PassHash,
        data: Base64String,
        checksum: Checksum,
    },
}

/// Describes the hash algorithm and value that is used for password
/// verification.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PassHash {
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
