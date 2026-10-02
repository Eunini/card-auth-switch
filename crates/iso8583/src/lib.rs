//! ISO 8583 message codec.
//!
//! * [`Spec`] - per-field specification table (content, length rule, data
//!   and prefix encodings). Built-in profiles: 1987 ASCII, 1987 BCD, 1987
//!   text, and a partial 1993 profile.
//! * [`Message`] - MTI + sparse data elements with spec-driven
//!   [`Message::encode`] / [`Message::decode`]. Decoding never panics on
//!   malformed input; it returns [`Error`].
//! * [`tlv`] - BER-TLV for EMV data in field 55.

mod error;
mod message;
mod mti;
mod reader;
pub mod spec;
pub mod tlv;

pub use error::{Error, Result};
pub use message::{mask_pan, Message};
pub use mti::Mti;
pub use spec::Spec;

/// Left-pad a numeric value with zeros to `width` (e.g. amounts, STAN).
pub fn pad_n(value: u64, width: usize) -> String {
    format!("{value:0width$}")
}

/// Right-pad text with spaces to exactly `width`, truncating if longer.
pub fn pad_ans(value: &str, width: usize) -> String {
    let mut s: String = value.chars().take(width).collect();
    while s.len() < width {
        s.push(' ');
    }
    s
}
