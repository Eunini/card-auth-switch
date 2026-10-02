//! ISO 9564-1 PIN block format 0 (a.k.a. ANSI X9.8 / ECI-0).
//!
//! ```text
//! PIN field: 0 | N | P P P P (P...) | F F ...      (16 nibbles)
//! PAN field: 0 0 0 0 | 12 rightmost PAN digits excluding the check digit
//! clear PIN block = PIN field XOR PAN field
//! ```

use crate::des3::{tdes_decrypt, tdes_encrypt, xor8};
use crate::{hex_to_bytes, CryptoError, Key16, Result};

fn pan_field(pan: &str) -> Result<[u8; 8]> {
    if pan.len() < 13 || pan.len() > 19 || !pan.bytes().all(|c| c.is_ascii_digit()) {
        return Err(CryptoError::Pan);
    }
    let digits = &pan[pan.len() - 13..pan.len() - 1];
    let b = hex_to_bytes(&format!("0000{digits}"))?;
    Ok(b.try_into().expect("8 bytes"))
}

pub fn validate_pin(pin: &str) -> Result<()> {
    if (4..=12).contains(&pin.len()) && pin.bytes().all(|c| c.is_ascii_digit()) {
        Ok(())
    } else {
        Err(CryptoError::Pin)
    }
}

/// Clear ISO format 0 PIN block.
pub fn encode_iso0(pin: &str, pan: &str) -> Result<[u8; 8]> {
    validate_pin(pin)?;
    let mut s = format!("0{:X}{pin}", pin.len());
    while s.len() < 16 {
        s.push('F');
    }
    let pin_field: [u8; 8] = hex_to_bytes(&s)?.try_into().expect("8 bytes");
    Ok(xor8(&pin_field, &pan_field(pan)?))
}

/// Recover the PIN from a clear ISO format 0 block, validating every
/// structural rule (control nibble, length, digits, filler).
pub fn decode_iso0(block: &[u8; 8], pan: &str) -> Result<String> {
    let f = xor8(block, &pan_field(pan)?);
    let nibble = |i: usize| -> u8 {
        let b = f[i / 2];
        if i.is_multiple_of(2) {
            b >> 4
        } else {
            b & 0xF
        }
    };
    if nibble(0) != 0 {
        return Err(CryptoError::PinBlockFormat("control field is not 0"));
    }
    let len = nibble(1) as usize;
    if !(4..=12).contains(&len) {
        return Err(CryptoError::PinBlockFormat("PIN length out of range"));
    }
    let mut pin = String::with_capacity(len);
    for i in 2..2 + len {
        let d = nibble(i);
        if d > 9 {
            return Err(CryptoError::PinBlockFormat("PIN digit is not numeric"));
        }
        pin.push((b'0' + d) as char);
    }
    for i in 2 + len..16 {
        if nibble(i) != 0xF {
            return Err(CryptoError::PinBlockFormat("filler is not F"));
        }
    }
    Ok(pin)
}

pub fn encrypt_iso0(key: &Key16, pin: &str, pan: &str) -> Result<[u8; 8]> {
    Ok(tdes_encrypt(key, &encode_iso0(pin, pan)?))
}

pub fn decrypt_iso0(key: &Key16, block: &[u8; 8], pan: &str) -> Result<String> {
    decode_iso0(&tdes_decrypt(key, block), pan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn round_trip(pin in "[0-9]{4,12}", pan in "[0-9]{13,19}", key in any::<[u8;16]>()) {
            let b = encrypt_iso0(&key, &pin, &pan).unwrap();
            prop_assert_eq!(decrypt_iso0(&key, &b, &pan).unwrap(), pin);
        }

        #[test]
        fn garbage_never_panics(block in any::<[u8;8]>(), pan in "[0-9]{13,19}") {
            let _ = decode_iso0(&block, &pan);
        }
    }

    #[test]
    fn wrong_pan_breaks_structure_or_pin() {
        let b = encode_iso0("1234", "5555555551234567").unwrap();
        assert_ne!(
            decode_iso0(&b, "5555555551234500").ok(),
            Some("1234".into())
        );
    }
}
