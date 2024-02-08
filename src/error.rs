#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("argument: {0}")]
    Argument(String),
    #[error("unknown command")]
    UnknownCommand,
    #[error("version mismatch: expected {0}, got {1}")]
    VersionMismatch(String, String),
    #[error("password verification")]
    PasswordVerification,
    #[error("password provider")]
    PasswordProvider,
    #[error("no trust")]
    NoTrust,
    #[error("unknown revision {0}")]
    UnknownRevision(String),
    #[error("shell {0}")]
    Shell(String),
    #[error("non interactive")]
    NonInteractive,
    #[error("parser error: {0}")]
    ParserError(String),
}
