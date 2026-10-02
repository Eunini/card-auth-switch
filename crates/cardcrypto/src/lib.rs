//! Payment card cryptography.
//!
//! Block ciphers come from the RustCrypto `des` crate; this crate only
//! implements the payment-industry *constructions* on top of them (PIN
//! block formats, PVV/CVV decimalisation, ISO 9797-1 MAC algorithm 3, EMV
//! key derivation and cryptogram methods).
//!
//! Every construction is tested against independently published vectors;
//! see `tests/vectors.rs` for sources.

pub mod cvv;
pub mod des3;
pub mod emv;
pub mod luhn;
pub mod mac;
pub mod pin;
pub mod pinblock;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid key length {0} (expected 16 bytes, double-length 3DES)")]
    KeyLength(usize),
    #[error("invalid PAN")]
    Pan,
    #[error("invalid PIN (must be 4-12 digits)")]
    Pin,
    #[error("PIN block format error: {0}")]
    PinBlockFormat(&'static str),
    #[error("invalid input: {0}")]
    Input(&'static str),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Double-length 3DES key (K1 || K2), the key size used throughout the
/// card payments world for ZPK/PVK/CVK/IMK.
pub type Key16 = [u8; 16];

pub fn key16(b: &[u8]) -> Result<Key16> {
    b.try_into().map_err(|_| CryptoError::KeyLength(b.len()))
}

/// Constant-time equality for comparing cryptograms, MACs, PVVs.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub(crate) fn digits_only(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// Hex digits to bytes (used for packing numeric data blocks).
pub(crate) fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(CryptoError::Input("odd hex length"));
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(CryptoError::Input("non-hex digit")),
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Ok((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

pub(crate) fn to_hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    b.iter()
        .flat_map(|x| [H[(x >> 4) as usize] as char, H[(x & 15) as usize] as char])
        .collect()
}

/// Standard decimalisation used by PVV and CVV: take the decimal digits of
/// the hex string left to right; if fewer than `n`, take the A-F digits
/// left to right and subtract 10.
pub(crate) fn decimalise(hex: &str, n: usize) -> String {
    let mut out: String = hex.chars().filter(|c| c.is_ascii_digit()).take(n).collect();
    if out.len() < n {
        for c in hex.chars().filter(|c| matches!(c, 'A'..='F')) {
            if out.len() == n {
                break;
            }
            out.push((b'0' + (c as u8 - b'A')) as char);
        }
    }
    out
}
