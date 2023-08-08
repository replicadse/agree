use anyhow::Result;

pub const VERSION_ID_LEN: usize = 36;
pub const VERSION_0_1: &'static str = "9f1e0683-7655-4f73-940a-38fa580b5725";

pub fn split_version_and_data(data: &Vec<u8>) -> Result<(String, &[u8])> {
    Ok((
        String::from_utf8(data[0..VERSION_ID_LEN].to_vec())?,
        &data[VERSION_ID_LEN..],
    ))
}

pub(crate) mod v1 {
    /// The archive that describes the single file storaing all information.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub(crate) struct Archive {
        /// Automatically generated unique ID of this archive.
        pub uid: String,
        /// The actual share of the secret.
        pub share: Share,

        /// This shares name.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Some plain text comment.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub comment: Option<String>,
        /// Some information about the secret.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub info: Option<SecretInfo>,
    }

    // Describing an individual share.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub(crate) enum Share {
        /// Plain base64 encoded share data.
        PlainBase64(String),
        /// Symmetrically encrypted, base64 encoded share data.
        EncryptedBase64 { hash: Hash, data: String },
    }

    /// Describes the hash algorithm and value that is used for password
    /// verification.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub(crate) enum Hash {
        /// Argon2id hash.
        Argon2id(String),
    }

    /// Describes the secret that has been sharded. Contains information about
    /// how to restore.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub(crate) struct SecretInfo {
        /// The amount of shares that were generated for the secret.
        pub num_shares: usize,
        /// The amount of shares that are needed for restoring the secret.
        pub threshold: usize,
    }
}
