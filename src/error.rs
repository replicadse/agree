#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("argument: {0}")]
    Argument(String),
    #[error("unknown command")]
    UnknownCommand,
    #[error("password verification")]
    PasswordVerification,
}
