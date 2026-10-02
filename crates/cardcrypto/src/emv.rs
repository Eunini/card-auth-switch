//! EMV application cryptograms (EMV 4.3 Book 2, Annex A1).
//!
//! Steps an issuer host performs to verify an ARQC:
//! 1. derive the ICC master key (MK-AC) from the issuer master key (IMK-AC)
//!    using PAN + PAN sequence number (option A, or option B for PANs > 16
//!    digits);
//! 2. derive the AC session key from MK-AC and the ATC (common session key
//!    derivation), unless the CVN uses MK-AC directly (Visa CVN 10);
//! 3. MAC the transaction data selected by the CDOL with ISO 9797-1 MAC
//!    algorithm 3 and compare with the ARQC;
//! 4. produce an ARPC (method 1: 3DES(ARQC xor ARC); method 2: MAC over
//!    ARQC || CSU || proprietary data) for issuer authentication.

use crate::des3::{adjust_parity, tdes_encrypt, xor8};
use crate::mac::{iso9797_alg3, Padding};
use crate::{digits_only, hex_to_bytes, CryptoError, Key16, Result};
use sha1::{Digest, Sha1};

fn derive_from_y(imk: &Key16, y: [u8; 8]) -> Key16 {
    let mut ny = y;
    for b in ny.iter_mut() {
        *b ^= 0xFF;
    }
    let l = tdes_encrypt(imk, &y);
    let r = tdes_encrypt(imk, &ny);
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&l);
    k[8..].copy_from_slice(&r);
    adjust_parity(&mut k);
    k
}

fn check_pan_psn(pan: &str, psn: &str) -> Result<()> {
    if pan.is_empty() || pan.len() > 19 || !digits_only(pan) {
        return Err(CryptoError::Pan);
    }
    if psn.len() != 2 || !digits_only(psn) {
        return Err(CryptoError::Input("PAN sequence number must be 2 digits"));
    }
    Ok(())
}

/// ICC master key derivation, option A (EMV Book 2 A1.4.1).
/// Y = rightmost 16 digits of PAN || PSN (left zero-padded);
/// MK = 3DES(IMK, Y) || 3DES(IMK, Y xor FF..FF), with odd parity.
pub fn derive_icc_mk_a(imk: &Key16, pan: &str, psn: &str) -> Result<Key16> {
    check_pan_psn(pan, psn)?;
    let s = format!("{pan}{psn}");
    let s = if s.len() > 16 {
        s[s.len() - 16..].to_string()
    } else {
        format!("{s:0>16}")
    };
    let y: [u8; 8] = hex_to_bytes(&s)?.try_into().expect("8 bytes");
    Ok(derive_from_y(imk, y))
}

/// ICC master key derivation, option B (EMV Book 2 A1.4.2), required for
/// PANs longer than 16 digits; identical to option A otherwise.
pub fn derive_icc_mk_b(imk: &Key16, pan: &str, psn: &str) -> Result<Key16> {
    check_pan_psn(pan, psn)?;
    if pan.len() <= 16 {
        return derive_icc_mk_a(imk, pan, psn);
    }
    let mut s = format!("{pan}{psn}");
    if s.len() % 2 == 1 {
        s.insert(0, '0');
    }
    let digest = Sha1::digest(hex_to_bytes(&s)?);
    let hex = crate::to_hex(&digest);
    let y_digits = crate::decimalise(&hex, 16);
    let y: [u8; 8] = hex_to_bytes(&y_digits)?.try_into().expect("8 bytes");
    Ok(derive_from_y(imk, y))
}

/// EMV common session key derivation (Book 2 A1.3.1) for an 8-byte block
/// cipher: SK = 3DES(MK, R with R[2]=F0) || 3DES(MK, R with R[2]=0F).
/// For AC keys R = ATC || 00 00 00 00 00 00.
pub fn derive_common_sk(mk: &Key16, r: &[u8; 8]) -> Key16 {
    let mut a = *r;
    a[2] = 0xF0;
    let mut b = *r;
    b[2] = 0x0F;
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&tdes_encrypt(mk, &a));
    k[8..].copy_from_slice(&tdes_encrypt(mk, &b));
    adjust_parity(&mut k);
    k
}

pub fn ac_session_r(atc: [u8; 2]) -> [u8; 8] {
    [atc[0], atc[1], 0, 0, 0, 0, 0, 0]
}

/// Application cryptogram (ARQC/TC/AAC) = ISO 9797-1 MAC alg 3 over the
/// CDOL data.
pub fn generate_ac(sk: &Key16, data: &[u8], padding: Padding) -> [u8; 8] {
    iso9797_alg3(sk, data, padding)
}

/// ARPC method 1 (Book 2 8.2.1): 3DES(SK, ARQC xor (ARC || 00*6)).
pub fn arpc_method1(sk: &Key16, arqc: &[u8; 8], arc: &[u8; 2]) -> [u8; 8] {
    let y = [arc[0], arc[1], 0, 0, 0, 0, 0, 0];
    tdes_encrypt(sk, &xor8(arqc, &y))
}

/// ARPC method 2 (Book 2 8.2.2): MAC alg 3 (padding method 2) over
/// ARQC || CSU || proprietary authentication data, leftmost 4 bytes.
pub fn arpc_method2(sk: &Key16, arqc: &[u8; 8], csu: &[u8; 4], prop: &[u8]) -> Result<[u8; 4]> {
    if prop.len() > 8 {
        return Err(CryptoError::Input("proprietary auth data max 8 bytes"));
    }
    let mut d = Vec::with_capacity(20);
    d.extend_from_slice(arqc);
    d.extend_from_slice(csu);
    d.extend_from_slice(prop);
    let m = iso9797_alg3(sk, &d, Padding::Method2);
    Ok([m[0], m[1], m[2], m[3]])
}

/// Terminal and card data elements that feed the ARQC (the minimum set
/// recommended by EMV Book 2 Table 26, as used by Visa CVN 10/18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArqcData {
    pub amount_authorised: [u8; 6], // 9F02, n12 BCD
    pub amount_other: [u8; 6],      // 9F03
    pub terminal_country: [u8; 2],  // 9F1A
    pub tvr: [u8; 5],               // 95
    pub currency: [u8; 2],          // 5F2A
    pub txn_date: [u8; 3],          // 9A YYMMDD
    pub txn_type: u8,               // 9C
    pub unpredictable: [u8; 4],     // 9F37
    pub aip: [u8; 2],               // 82
    pub atc: [u8; 2],               // 9F36
    pub iad: Vec<u8>,               // 9F10
}

/// Cryptogram Version Number: which derivation/MAC/ARPC methods a card
/// uses. Read from the Issuer Application Data (9F10) byte 3 for Visa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cvn {
    /// Visa CVN 10: MK-AC (option A) used directly, MAC padding method 1,
    /// data ends with the 4-byte CVR, ARPC method 1.
    Visa10,
    /// Visa CVN 18: MK-AC (option B), common session key from ATC, padding
    /// method 2, data ends with the full IAD, ARPC method 2.
    Visa18,
}

impl Cvn {
    pub fn from_iad(iad: &[u8]) -> Option<Cvn> {
        match iad.get(2) {
            Some(0x0A) => Some(Cvn::Visa10),
            Some(0x12) => Some(Cvn::Visa18),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Cvn::Visa10 => 10,
            Cvn::Visa18 => 18,
        }
    }

    pub fn from_code(c: u8) -> Option<Cvn> {
        match c {
            10 => Some(Cvn::Visa10),
            18 => Some(Cvn::Visa18),
            _ => None,
        }
    }

    pub fn icc_mk(self, imk: &Key16, pan: &str, psn: &str) -> Result<Key16> {
        match self {
            Cvn::Visa10 => derive_icc_mk_a(imk, pan, psn),
            Cvn::Visa18 => derive_icc_mk_b(imk, pan, psn),
        }
    }

    pub fn ac_key(self, icc_mk: &Key16, atc: [u8; 2]) -> Key16 {
        match self {
            Cvn::Visa10 => *icc_mk,
            Cvn::Visa18 => derive_common_sk(icc_mk, &ac_session_r(atc)),
        }
    }

    pub fn padding(self) -> Padding {
        match self {
            Cvn::Visa10 => Padding::Method1,
            Cvn::Visa18 => Padding::Method2,
        }
    }

    /// Concatenate CDOL1 data in the order the card MACs it.
    pub fn ac_data(self, d: &ArqcData) -> Result<Vec<u8>> {
        let mut v = Vec::with_capacity(48);
        v.extend_from_slice(&d.amount_authorised);
        v.extend_from_slice(&d.amount_other);
        v.extend_from_slice(&d.terminal_country);
        v.extend_from_slice(&d.tvr);
        v.extend_from_slice(&d.currency);
        v.extend_from_slice(&d.txn_date);
        v.push(d.txn_type);
        v.extend_from_slice(&d.unpredictable);
        v.extend_from_slice(&d.aip);
        v.extend_from_slice(&d.atc);
        match self {
            Cvn::Visa10 => {
                let cvr = d
                    .iad
                    .get(3..7)
                    .ok_or(CryptoError::Input("IAD too short for CVR"))?;
                v.extend_from_slice(cvr);
            }
            Cvn::Visa18 => v.extend_from_slice(&d.iad),
        }
        Ok(v)
    }

    /// Card side: compute the ARQC.
    pub fn generate_arqc(self, icc_mk: &Key16, d: &ArqcData) -> Result<[u8; 8]> {
        let sk = self.ac_key(icc_mk, d.atc);
        Ok(generate_ac(&sk, &self.ac_data(d)?, self.padding()))
    }
}

/// Issuer response data for tag 91 (Issuer Authentication Data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpcResponse {
    /// Method 1: ARPC (8) || ARC (2).
    Method1 { arpc: [u8; 8], arc: [u8; 2] },
    /// Method 2: ARPC (4) || CSU (4).
    Method2 { arpc: [u8; 4], csu: [u8; 4] },
}

impl ArpcResponse {
    pub fn to_tag91(&self) -> Vec<u8> {
        match self {
            ArpcResponse::Method1 { arpc, arc } => [&arpc[..], &arc[..]].concat(),
            ArpcResponse::Method2 { arpc, csu } => [&arpc[..], &csu[..]].concat(),
        }
    }
}

/// Card side: verify the issuer's ARPC (issuer authentication).
pub fn card_verify_arpc(
    cvn: Cvn,
    icc_mk: &Key16,
    atc: [u8; 2],
    arqc: &[u8; 8],
    tag91: &[u8],
) -> bool {
    let sk = cvn.ac_key(icc_mk, atc);
    match (cvn, tag91.len()) {
        (Cvn::Visa10, 10) => {
            let arc = [tag91[8], tag91[9]];
            crate::ct_eq(&arpc_method1(&sk, arqc, &arc), &tag91[..8])
        }
        (Cvn::Visa18, 8) => {
            let csu = [tag91[4], tag91[5], tag91[6], tag91[7]];
            match arpc_method2(&sk, arqc, &csu, &[]) {
                Ok(a) => crate::ct_eq(&a, &tag91[..4]),
                Err(_) => false,
            }
        }
        _ => false,
    }
}
