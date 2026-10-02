//! Wire protocol of the simulated HSM.
//!
//! Frames are a 2-byte big-endian length followed by a JSON document.
//! Requests carry an `id` so many commands can be in flight on one
//! connection; responses may come back out of order.
//!
//! Keys only ever cross this interface as LMK-wrapped key blocks (or, for
//! import, encrypted under a ZMK). No command returns a clear key or a
//! clear PIN.

use serde::{Deserialize, Serialize};

/// Key usage, encoded in the key block header using TR-31 usage codes so
/// a block wrapped for one purpose cannot be used for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Zone master key / key-encrypting key (TR-31 `K0`).
    Zmk,
    /// Zone PIN key: encrypts PIN blocks between acquirer and switch (`P0`).
    Zpk,
    /// PIN verification key, Visa PVV or IBM 3624 (`V2`).
    Pvk,
    /// Card verification key for CVV/CVC (`C0`).
    Cvk,
    /// Issuer master key for application cryptograms (`E0`).
    ImkAc,
}

impl KeyType {
    pub fn usage_code(self) -> &'static str {
        match self {
            KeyType::Zmk => "K0",
            KeyType::Zpk => "P0",
            KeyType::Pvk => "V2",
            KeyType::Cvk => "C0",
            KeyType::ImkAc => "E0",
        }
    }

    pub fn from_usage_code(c: &str) -> Option<KeyType> {
        Some(match c {
            "K0" => KeyType::Zmk,
            "P0" => KeyType::Zpk,
            "V2" => KeyType::Pvk,
            "C0" => KeyType::Cvk,
            "E0" => KeyType::ImkAc,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<KeyType> {
        Some(match s.to_ascii_uppercase().as_str() {
            "ZMK" => KeyType::Zmk,
            "ZPK" => KeyType::Zpk,
            "PVK" => KeyType::Pvk,
            "CVK" => KeyType::Cvk,
            "IMK" | "IMK-AC" | "IMKAC" => KeyType::ImkAc,
            _ => return None,
        })
    }
}

/// ARPC to produce after a successful ARQC verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArpcMethod {
    /// EMV method 1 with a 2-byte Authorisation Response Code (hex).
    Method1 { arc: String },
    /// EMV method 2 with a 4-byte Card Status Update and optional
    /// proprietary authentication data (hex).
    Method2 { csu: String, prop: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Command {
    Echo {
        data: String,
    },
    /// LMK check value and firmware string.
    Diagnostics,
    /// Generate a random key and return it under the LMK.
    GenerateKey {
        key_type: KeyType,
    },
    /// Form a key from clear components (XOR). Only allowed while the HSM is
    /// in "authorized state", which models the physical key / officer
    /// PINs a real HSM requires for a key ceremony.
    FormKeyFromComponents {
        key_type: KeyType,
        components: Vec<String>,
    },
    /// Import a key received from another zone encrypted under a shared ZMK.
    ImportKey {
        key_type: KeyType,
        zmk: String,
        key_under_zmk: String,
    },
    KeyCheckValue {
        key_type: KeyType,
        key: String,
    },
    /// Decrypt the ISO-0 PIN block under the ZPK and verify against a Visa PVV.
    VerifyPinPvv {
        zpk: String,
        pvk: String,
        pin_block: String,
        pan: String,
        pvki: u8,
        pvv: String,
    },
    /// Decrypt the ISO-0 PIN block under the ZPK and verify with IBM 3624 offset.
    VerifyPinIbm3624 {
        zpk: String,
        pvk: String,
        pin_block: String,
        pan: String,
        offset: String,
        decimalisation_table: String,
        pan_offset: usize,
        pan_length: usize,
    },
    /// Re-encrypt an ISO-0 PIN block from one ZPK to another.
    TranslatePin {
        src_zpk: String,
        dst_zpk: String,
        pin_block: String,
        pan: String,
    },
    /// Issuance: PVV for an encrypted PIN (the PIN is never in clear outside).
    GeneratePvv {
        zpk: String,
        pvk: String,
        pin_block: String,
        pan: String,
        pvki: u8,
    },
    GenerateCvv {
        cvk: String,
        pan: String,
        expiry: String,
        service_code: String,
    },
    VerifyCvv {
        cvk: String,
        pan: String,
        expiry: String,
        service_code: String,
        cvv: String,
    },
    /// Derive MK-AC from the IMK (per CVN), the AC session key from the ATC,
    /// verify the ARQC over `data` and, if valid, produce the ARPC.
    VerifyArqc {
        imk_ac: String,
        cvn: u8,
        pan: String,
        psn: String,
        atc: String,
        data: String,
        arqc: String,
        arpc: Option<ArpcMethod>,
    },
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Echo { .. } => "Echo",
            Command::Diagnostics => "Diagnostics",
            Command::GenerateKey { .. } => "GenerateKey",
            Command::FormKeyFromComponents { .. } => "FormKeyFromComponents",
            Command::ImportKey { .. } => "ImportKey",
            Command::KeyCheckValue { .. } => "KeyCheckValue",
            Command::VerifyPinPvv { .. } => "VerifyPinPvv",
            Command::VerifyPinIbm3624 { .. } => "VerifyPinIbm3624",
            Command::TranslatePin { .. } => "TranslatePin",
            Command::GeneratePvv { .. } => "GeneratePvv",
            Command::GenerateCvv { .. } => "GenerateCvv",
            Command::VerifyCvv { .. } => "VerifyCvv",
            Command::VerifyArqc { .. } => "VerifyArqc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply")]
pub enum Reply {
    Echo {
        data: String,
    },
    Diagnostics {
        lmk_kcv: String,
        firmware: String,
    },
    Key {
        key_block: String,
        kcv: String,
    },
    Kcv {
        kcv: String,
    },
    /// Outcome of a verification command. `false` is a business result
    /// (wrong PIN, bad cryptogram), not an error.
    Verified {
        ok: bool,
    },
    PinBlock {
        pin_block: String,
    },
    Pvv {
        pvv: String,
    },
    Cvv {
        cvv: String,
    },
    Arqc {
        ok: bool,
        tag91: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum HsmError {
    #[error("malformed request: {0}")]
    Malformed(String),
    #[error("key block rejected: {0}")]
    KeyBlock(String),
    #[error("key usage mismatch: expected {expected}")]
    KeyUsage { expected: String },
    #[error("PIN block format error: {0}")]
    PinBlockFormat(String),
    #[error("invalid data: {0}")]
    Data(String),
    #[error("command not permitted: {0}")]
    NotPermitted(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub cmd: Command,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub result: Result<Reply, HsmError>,
}
