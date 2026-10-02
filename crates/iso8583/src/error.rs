use thiserror::Error;

/// Every way decoding or encoding can fail. Decoding untrusted bytes must
/// always end in one of these, never in a panic.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("truncated input while reading {what}: need {need} bytes, {have} available")]
    Truncated {
        what: &'static str,
        need: usize,
        have: usize,
    },
    #[error("invalid MTI {0:?}")]
    InvalidMti(String),
    #[error("MTI version {found} does not match spec version {expected}")]
    MtiVersion { expected: char, found: char },
    #[error("tertiary bitmap (bit 65 of an extended bitmap) is not supported")]
    TertiaryBitmap,
    #[error("field {0} is set in the bitmap but has no definition in the spec")]
    UndefinedField(u8),
    #[error("field {field}: {reason}")]
    Field { field: u8, reason: String },
    #[error("{0} trailing bytes after the last field")]
    TrailingBytes(usize),
    #[error("invalid field number {0}")]
    InvalidFieldNumber(usize),
    #[error("TLV: {0}")]
    Tlv(String),
}

impl Error {
    pub(crate) fn field(field: u8, reason: impl Into<String>) -> Self {
        Error::Field {
            field,
            reason: reason.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
