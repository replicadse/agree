#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Archive {
    /// Version of this program with which the secret has been generated
    pub version: String,

    /// This shares name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Some plain text comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Some information about the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<SecretInfo>,

    /// The actual share of the secret.
    pub share: Share,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum Share {
    PlainBase64(String),
    EncryptedBase64 { hash: Hash, data: String },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum Hash {
    Argon2id(String),
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct SecretInfo {
    /// The amount of shares that were generated for the secret.
    pub num_shares: usize,
    /// The amount of shares that are needed for restoring the secret.
    pub threshold: usize,
}
