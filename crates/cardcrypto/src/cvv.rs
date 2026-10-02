//! Visa CVV / Mastercard CVC (CVV1 on track, CVV2 printed, iCVV in chip
//! track 2 equivalent; they differ only in the service code input).

use crate::des3::{des_encrypt, tdes_encrypt, xor8};
use crate::{decimalise, digits_only, hex_to_bytes, to_hex, CryptoError, Key16, Result};

/// CVV over PAN || expiry (YYMM) || service code, zero-padded to 32 digits.
/// Block 1 is DES-encrypted with CVK-A, XORed with block 2, 3DES-encrypted
/// with CVK-A/B; three digits are taken after decimalisation.
pub fn cvv(cvk: &Key16, pan: &str, expiry_yymm: &str, service_code: &str) -> Result<String> {
    if pan.is_empty() || pan.len() > 19 || !digits_only(pan) {
        return Err(CryptoError::Pan);
    }
    if expiry_yymm.len() != 4 || !digits_only(expiry_yymm) {
        return Err(CryptoError::Input("expiry must be YYMM"));
    }
    if service_code.len() != 3 || !digits_only(service_code) {
        return Err(CryptoError::Input("service code must be 3 digits"));
    }
    let mut data = format!("{pan}{expiry_yymm}{service_code}");
    while data.len() < 32 {
        data.push('0');
    }
    let bytes = hex_to_bytes(&data)?;
    let b1: [u8; 8] = bytes[..8].try_into().expect("8");
    let b2: [u8; 8] = bytes[8..16].try_into().expect("8");
    let ka: [u8; 8] = cvk[..8].try_into().expect("8");
    let r = tdes_encrypt(cvk, &xor8(&des_encrypt(&ka, &b1), &b2));
    Ok(decimalise(&to_hex(&r), 3))
}

pub fn verify_cvv(
    cvk: &Key16,
    pan: &str,
    expiry_yymm: &str,
    service_code: &str,
    value: &str,
) -> Result<bool> {
    Ok(crate::ct_eq(
        cvv(cvk, pan, expiry_yymm, service_code)?.as_bytes(),
        value.as_bytes(),
    ))
}
