use std::fmt;

/// Ошибка плагина сохраняет имя операции и исходный числовой код.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Load(String),
    MissingSymbol(&'static str),
    Native { operation: &'static str, code: i32 },
    InvalidInput(&'static str),
    InvalidOutput(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(message) => write!(f, "Cannot load crypto plugin: {message}"),
            Self::MissingSymbol(name) => write!(f, "Missing crypto plugin export: {name}"),
            Self::Native { operation, code } => write!(f, "{operation}: native error {code}"),
            Self::InvalidInput(message) | Self::InvalidOutput(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
