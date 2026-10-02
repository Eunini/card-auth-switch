//! PIN verification methods: Visa PVV and IBM 3624 (natural PIN + offset).

use crate::des3::tdes_encrypt;
use crate::{decimalise, digits_only, hex_to_bytes, to_hex, CryptoError, Key16, Result};

/// Visa PIN Verification Value.
///
/// TSP = 11 rightmost PAN digits excluding the check digit || PVKI (1
/// digit) || 4 PIN digits. PVV = first 4 decimal digits of 3DES(PVK, TSP)
/// after standard decimalisation.
pub fn visa_pvv(pvk: &Key16, pvki: u8, pin: &str, pan: &str) -> Result<String> {
    if pvki > 9 {
        return Err(CryptoError::Input("PVKI must be 0-9"));
    }
    if pin.len() != 4 || !digits_only(pin) {
        return Err(CryptoError::Input("PVV needs a 4 digit PIN"));
    }
    if pan.len() < 12 || !digits_only(pan) {
        return Err(CryptoError::Pan);
    }
    let tsp = format!("{}{}{}", &pan[pan.len() - 12..pan.len() - 1], pvki, pin);
    let block: [u8; 8] = hex_to_bytes(&tsp)?.try_into().expect("8 bytes");
    Ok(decimalise(&to_hex(&tdes_encrypt(pvk, &block)), 4))
}

/// IBM 3624 parameters.
#[derive(Debug, Clone)]
pub struct Ibm3624 {
    /// 16-digit decimalisation table mapping hex nibble 0-F to a digit.
    pub decimalisation_table: String,
    /// Start of validation data within the PAN.
    pub pan_offset: usize,
    /// Length of validation data (<= 16).
    pub pan_length: usize,
    /// Hex digit used to right-pad validation data to 16 digits.
    pub pad: char,
}

impl Ibm3624 {
    fn intermediate(&self, pvk: &Key16, pan: &str) -> Result<String> {
        let table = self.decimalisation_table.as_bytes();
        if table.len() != 16 || !digits_only(&self.decimalisation_table) {
            return Err(CryptoError::Input("decimalisation table must be 16 digits"));
        }
        if !digits_only(pan) || self.pan_length > 16 || self.pan_length == 0 {
            return Err(CryptoError::Pan);
        }
        let vd = pan
            .get(self.pan_offset..self.pan_offset + self.pan_length)
            .ok_or(CryptoError::Pan)?;
        let mut v = vd.to_string();
        while v.len() < 16 {
            v.push(self.pad);
        }
        let block: [u8; 8] = hex_to_bytes(&v)?.try_into().expect("8 bytes");
        let enc = to_hex(&tdes_encrypt(pvk, &block));
        Ok(enc
            .bytes()
            .map(|c| {
                let i = if c.is_ascii_digit() {
                    c - b'0'
                } else {
                    c - b'A' + 10
                };
                table[i as usize] as char
            })
            .collect())
    }

    /// Natural PIN plus offset (digit-wise, mod 10).
    pub fn derive_pin(&self, pvk: &Key16, pan: &str, offset: &str) -> Result<String> {
        if !(4..=12).contains(&offset.len()) || !digits_only(offset) {
            return Err(CryptoError::Input("offset must be 4-12 digits"));
        }
        let nat = self.intermediate(pvk, pan)?;
        Ok(nat
            .bytes()
            .zip(offset.bytes())
            .map(|(n, o)| (b'0' + ((n - b'0') + (o - b'0')) % 10) as char)
            .collect())
    }

    /// Offset that maps the natural PIN to the customer-selected `pin`.
    pub fn offset_for(&self, pvk: &Key16, pan: &str, pin: &str) -> Result<String> {
        crate::pinblock::validate_pin(pin)?;
        let nat = self.intermediate(pvk, pan)?;
        Ok(pin
            .bytes()
            .zip(nat.bytes())
            .map(|(p, n)| (b'0' + (10 + (p - b'0') - (n - b'0')) % 10) as char)
            .collect())
    }
}

/// Constant-time PVV comparison.
pub fn verify_pvv(pvk: &Key16, pvki: u8, pin: &str, pan: &str, pvv: &str) -> Result<bool> {
    Ok(crate::ct_eq(
        visa_pvv(pvk, pvki, pin, pan)?.as_bytes(),
        pvv.as_bytes(),
    ))
}
