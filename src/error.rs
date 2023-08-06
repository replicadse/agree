#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("generic: {0}")]
    Generic(String),
    #[error("many: {0:?}")]
    Many(Vec<anyhow::Error>),

    // ExperimentalCommand,
    #[error("argument: {0}")]
    Argument(String),
    #[error("unknown command")]
    UnknownCommand,
}
