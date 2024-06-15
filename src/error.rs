#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("experimental: {0}")]
    Experimental(String),
    #[error("argument: {0}")]
    Argument(String),
    #[error("unknown command")]
    UnknownCommand,
    #[error("password verification")]
    PasswordVerification,
    #[error("password provider")]
    PasswordProvider,
    #[error("no trust")]
    NoTrust,
    #[error("non interactive")]
    NonInteractive,
    #[error("decoding error: {0}")]
    Decoding(String),
    #[error("mismatched shares")]
    MismatchedShares,
    #[error("checksum failed")]
    ChecksumFailed,
    #[error("password mismatch")]
    PasswordMismatch,

    #[cfg(test)]
    #[error("shell {0}")]
    Shell(String),
}
