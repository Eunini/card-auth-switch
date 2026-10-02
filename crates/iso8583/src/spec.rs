//! Field specification tables.
//!
//! A [`Spec`] is the single source of truth for how each data element is
//! laid out on the wire: its content type (n, an, ans, z, b ...), its length
//! rule (fixed, LLVAR, LLLVAR) and how both the data and any length prefix are
//! encoded (ASCII, packed BCD or raw binary). The codec itself contains no
//! per-field knowledge; changing a network profile means changing the table,
//! not the code.

/// ISO 8583 content (character set) of a data element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// `n` numeric digits 0-9.
    N,
    /// `a` alphabetic (spaces tolerated, as seen in practice).
    A,
    /// `an` alphanumeric (spaces tolerated).
    An,
    /// `ans` alphanumeric and special: printable ASCII 0x20..=0x7E.
    Ans,
    /// `ns` numeric and special.
    Ns,
    /// `z` track 2/3 code set: digits plus the field separator `=` (`D` in BCD).
    Z,
    /// `x+n` amount with a leading `C`/`D` sign; length includes the sign.
    XN,
    /// `b` binary data; lengths are in bytes.
    B,
}

/// Length rule. For `Fixed` the value is the exact length, for variable
/// fields it is the maximum. Units are characters/digits, or bytes for `b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Length {
    Fixed(usize),
    LlVar(usize),
    LllVar(usize),
}

impl Length {
    pub fn max(self) -> usize {
        match self {
            Length::Fixed(n) | Length::LlVar(n) | Length::LllVar(n) => n,
        }
    }
}

/// Wire encoding of the field data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// One ASCII character per unit. For `b` fields this means two hex
    /// characters per byte.
    Ascii,
    /// Packed BCD, two digits per byte. Only valid for `n` and `z` content.
    Bcd,
    /// Raw bytes. Only valid for `b` content.
    Binary,
}

/// Wire encoding of the LL/LLL length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixEncoding {
    /// "LL" = 2 ASCII digits, "LLL" = 3 ASCII digits.
    Ascii,
    /// "LL" = 1 BCD byte, "LLL" = 2 BCD bytes (leading nibble zero).
    Bcd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub content: Content,
    pub length: Length,
    pub encoding: Encoding,
    pub prefix: PrefixEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtiEncoding {
    Ascii,
    Bcd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapEncoding {
    /// 8 raw bytes per bitmap.
    Binary,
    /// 16 hex characters per bitmap.
    Hex,
}

/// ISO 8583 version as carried in the first MTI digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1987,
    V1993,
}

impl Version {
    pub fn mti_digit(self) -> char {
        match self {
            Version::V1987 => '0',
            Version::V1993 => '1',
        }
    }
}

/// A complete wire profile.
#[derive(Debug, Clone)]
pub struct Spec {
    pub name: &'static str,
    pub version: Version,
    pub mti_encoding: MtiEncoding,
    pub bitmap_encoding: BitmapEncoding,
    fields: [Option<FieldSpec>; 129],
}

const fn f(name: &'static str, content: Content, length: Length) -> Option<FieldSpec> {
    Some(FieldSpec {
        name,
        content,
        length,
        encoding: Encoding::Ascii,
        prefix: PrefixEncoding::Ascii,
    })
}

use Content::*;
use Length::*;

/// ISO 8583:1987 data element definitions (content and length only; the
/// encodings are applied by a profile constructor).
fn base_1987() -> [Option<FieldSpec>; 129] {
    let mut t: [Option<FieldSpec>; 129] = [None; 129];
    t[1] = f("Secondary bitmap", B, Fixed(8));
    t[2] = f("Primary account number", N, LlVar(19));
    t[3] = f("Processing code", N, Fixed(6));
    t[4] = f("Amount, transaction", N, Fixed(12));
    t[5] = f("Amount, settlement", N, Fixed(12));
    t[6] = f("Amount, cardholder billing", N, Fixed(12));
    t[7] = f("Transmission date and time", N, Fixed(10));
    t[8] = f("Amount, cardholder billing fee", N, Fixed(8));
    t[9] = f("Conversion rate, settlement", N, Fixed(8));
    t[10] = f("Conversion rate, cardholder billing", N, Fixed(8));
    t[11] = f("System trace audit number", N, Fixed(6));
    t[12] = f("Time, local transaction (hhmmss)", N, Fixed(6));
    t[13] = f("Date, local transaction (MMDD)", N, Fixed(4));
    t[14] = f("Date, expiration (YYMM)", N, Fixed(4));
    t[15] = f("Date, settlement", N, Fixed(4));
    t[16] = f("Date, conversion", N, Fixed(4));
    t[17] = f("Date, capture", N, Fixed(4));
    t[18] = f("Merchant type (MCC)", N, Fixed(4));
    t[19] = f("Acquiring institution country code", N, Fixed(3));
    t[20] = f("PAN extended, country code", N, Fixed(3));
    t[21] = f("Forwarding institution country code", N, Fixed(3));
    t[22] = f("Point of service entry mode", N, Fixed(3));
    t[23] = f("Card sequence number", N, Fixed(3));
    t[24] = f("Network international identifier", N, Fixed(3));
    t[25] = f("Point of service condition code", N, Fixed(2));
    t[26] = f("Point of service capture code", N, Fixed(2));
    t[27] = f("Authorizing identification response length", N, Fixed(1));
    t[28] = f("Amount, transaction fee", XN, Fixed(9));
    t[29] = f("Amount, settlement fee", XN, Fixed(9));
    t[30] = f("Amount, transaction processing fee", XN, Fixed(9));
    t[31] = f("Amount, settlement processing fee", XN, Fixed(9));
    t[32] = f("Acquiring institution identification code", N, LlVar(11));
    t[33] = f("Forwarding institution identification code", N, LlVar(11));
    t[34] = f("Primary account number, extended", Ns, LlVar(28));
    t[35] = f("Track 2 data", Z, LlVar(37));
    t[36] = f("Track 3 data", N, LllVar(104));
    t[37] = f("Retrieval reference number", An, Fixed(12));
    t[38] = f("Authorization identification response", An, Fixed(6));
    t[39] = f("Response code", An, Fixed(2));
    t[40] = f("Service restriction code", An, Fixed(3));
    t[41] = f("Card acceptor terminal identification", Ans, Fixed(8));
    t[42] = f("Card acceptor identification code", Ans, Fixed(15));
    t[43] = f("Card acceptor name/location", Ans, Fixed(40));
    t[44] = f("Additional response data", An, LlVar(25));
    t[45] = f("Track 1 data", Ans, LlVar(76));
    t[46] = f("Additional data - ISO", Ans, LllVar(999));
    t[47] = f("Additional data - national", Ans, LllVar(999));
    t[48] = f("Additional data - private", Ans, LllVar(999));
    t[49] = f("Currency code, transaction", N, Fixed(3));
    t[50] = f("Currency code, settlement", N, Fixed(3));
    t[51] = f("Currency code, cardholder billing", N, Fixed(3));
    t[52] = f("Personal identification number data", B, Fixed(8));
    t[53] = f("Security related control information", N, Fixed(16));
    t[54] = f("Additional amounts", An, LllVar(120));
    // Field 55 is "reserved ISO" in 1987; networks use it for EMV (BER-TLV).
    t[55] = f("ICC data (EMV, BER-TLV)", B, LllVar(255));
    t[56] = f("Reserved ISO", Ans, LllVar(999));
    for slot in t.iter_mut().take(60).skip(57) {
        *slot = f("Reserved national", Ans, LllVar(999));
    }
    for slot in t.iter_mut().take(64).skip(60) {
        *slot = f("Reserved private", Ans, LllVar(999));
    }
    t[64] = f("Message authentication code", B, Fixed(8));
    t[65] = f("Tertiary bitmap", B, Fixed(8));
    t[66] = f("Settlement code", N, Fixed(1));
    t[67] = f("Extended payment code", N, Fixed(2));
    t[68] = f("Receiving institution country code", N, Fixed(3));
    t[69] = f("Settlement institution country code", N, Fixed(3));
    t[70] = f("Network management information code", N, Fixed(3));
    t[71] = f("Message number", N, Fixed(4));
    t[72] = f("Message number, last", N, Fixed(4));
    t[73] = f("Date, action (YYMMDD)", N, Fixed(6));
    t[74] = f("Credits, number", N, Fixed(10));
    t[75] = f("Credits, reversal number", N, Fixed(10));
    t[76] = f("Debits, number", N, Fixed(10));
    t[77] = f("Debits, reversal number", N, Fixed(10));
    t[78] = f("Transfer, number", N, Fixed(10));
    t[79] = f("Transfer, reversal number", N, Fixed(10));
    t[80] = f("Inquiries, number", N, Fixed(10));
    t[81] = f("Authorizations, number", N, Fixed(10));
    t[82] = f("Credits, processing fee amount", N, Fixed(12));
    t[83] = f("Credits, transaction fee amount", N, Fixed(12));
    t[84] = f("Debits, processing fee amount", N, Fixed(12));
    t[85] = f("Debits, transaction fee amount", N, Fixed(12));
    t[86] = f("Credits, amount", N, Fixed(16));
    t[87] = f("Credits, reversal amount", N, Fixed(16));
    t[88] = f("Debits, amount", N, Fixed(16));
    t[89] = f("Debits, reversal amount", N, Fixed(16));
    t[90] = f("Original data elements", N, Fixed(42));
    t[91] = f("File update code", An, Fixed(1));
    t[92] = f("File security code", An, Fixed(2));
    t[93] = f("Response indicator", An, Fixed(5));
    t[94] = f("Service indicator", An, Fixed(7));
    t[95] = f("Replacement amounts", An, Fixed(42));
    t[96] = f("Message security code", B, Fixed(8));
    t[97] = f("Amount, net settlement", XN, Fixed(17));
    t[98] = f("Payee", Ans, Fixed(25));
    t[99] = f("Settlement institution identification code", N, LlVar(11));
    t[100] = f("Receiving institution identification code", N, LlVar(11));
    t[101] = f("File name", Ans, LlVar(17));
    t[102] = f("Account identification 1", Ans, LlVar(28));
    t[103] = f("Account identification 2", Ans, LlVar(28));
    t[104] = f("Transaction description", Ans, LllVar(100));
    for slot in t.iter_mut().take(112).skip(105) {
        *slot = f("Reserved ISO", Ans, LllVar(999));
    }
    for slot in t.iter_mut().take(120).skip(112) {
        *slot = f("Reserved national", Ans, LllVar(999));
    }
    for slot in t.iter_mut().take(128).skip(120) {
        *slot = f("Reserved private", Ans, LllVar(999));
    }
    t[128] = f("Message authentication code", B, Fixed(8));
    t
}

impl Spec {
    /// ISO 8583:1987, ASCII MTI, binary bitmaps, ASCII data and ASCII
    /// length prefixes, raw binary for `b` fields. This is the profile the
    /// switch speaks on its acquirer interface.
    pub fn v1987_ascii() -> Self {
        let mut fields = base_1987();
        for fs in fields.iter_mut().flatten() {
            fs.encoding = if fs.content == Content::B {
                Encoding::Binary
            } else {
                Encoding::Ascii
            };
            fs.prefix = PrefixEncoding::Ascii;
        }
        Spec {
            name: "ISO8583:1987 ASCII",
            version: Version::V1987,
            mti_encoding: MtiEncoding::Ascii,
            bitmap_encoding: BitmapEncoding::Binary,
            fields,
        }
    }

    /// ISO 8583:1987 with packed BCD numerics, BCD MTI and BCD length
    /// prefixes (common on POS terminal and some host-to-host links).
    pub fn v1987_bcd() -> Self {
        let mut fields = base_1987();
        for fs in fields.iter_mut().flatten() {
            fs.encoding = match fs.content {
                Content::N | Content::Z => Encoding::Bcd,
                Content::B => Encoding::Binary,
                _ => Encoding::Ascii,
            };
            fs.prefix = PrefixEncoding::Bcd;
        }
        Spec {
            name: "ISO8583:1987 BCD",
            version: Version::V1987,
            mti_encoding: MtiEncoding::Bcd,
            bitmap_encoding: BitmapEncoding::Binary,
            fields,
        }
    }

    /// ISO 8583:1987 with everything printable: hex bitmaps and hex-encoded
    /// binary fields. Useful for text-only transports and logs.
    pub fn v1987_text() -> Self {
        let mut s = Self::v1987_ascii();
        s.name = "ISO8583:1987 text";
        s.bitmap_encoding = BitmapEncoding::Hex;
        for fs in s.fields.iter_mut().flatten() {
            fs.encoding = Encoding::Ascii;
        }
        s
    }

    /// A partial ISO 8583:1993 profile showing the main structural
    /// differences from 1987 (see docs/design.md). Only the elements whose
    /// format changed and that this project uses are redefined.
    pub fn v1993_ascii() -> Self {
        let mut s = Self::v1987_ascii();
        s.name = "ISO8583:1993 ASCII (partial)";
        s.version = Version::V1993;
        let ascii = |name, content, length| {
            Some(FieldSpec {
                name,
                content,
                length,
                encoding: Encoding::Ascii,
                prefix: PrefixEncoding::Ascii,
            })
        };
        // Local date and time merged into one YYMMDDhhmmss element.
        s.fields[12] = ascii("Date and time, local transaction", N, Fixed(12));
        s.fields[13] = ascii("Date, effective (YYMM)", N, Fixed(4));
        // POS entry mode (n3) replaced by a 12-position POS data code.
        s.fields[22] = ascii("Point of service data code", An, Fixed(12));
        // Function code replaces the NII.
        s.fields[24] = ascii("Function code", N, Fixed(3));
        // Message reason code replaces POS condition code.
        s.fields[25] = ascii("Message reason code", N, Fixed(4));
        // Response code (an2) becomes a 3-digit action code.
        s.fields[39] = ascii("Action code", N, Fixed(3));
        // Card acceptor name/location becomes variable.
        s.fields[43] = ascii("Card acceptor name/location", Ans, LlVar(99));
        // Original data elements move to LLVAR field 56; 90 is reserved.
        s.fields[56] = ascii("Original data elements", N, LlVar(35));
        s.fields[90] = ascii("Reserved ISO", Ans, LllVar(999));
        s
    }

    pub fn field(&self, n: u8) -> Option<&FieldSpec> {
        self.fields.get(n as usize).and_then(|f| f.as_ref())
    }

    /// Override a single element definition (e.g. a private-use field).
    pub fn set_field(&mut self, n: u8, spec: FieldSpec) {
        if (2..=128).contains(&n) {
            self.fields[n as usize] = Some(spec);
        }
    }

    /// Check the table for impossible combinations (e.g. BCD alphanumerics).
    pub fn validate(&self) -> Result<(), String> {
        for (i, fs) in self.fields.iter().enumerate() {
            let Some(fs) = fs else { continue };
            match (fs.content, fs.encoding) {
                (Content::N | Content::Z, Encoding::Bcd) => {}
                (_, Encoding::Bcd) => {
                    return Err(format!("field {i}: BCD is only valid for n and z"))
                }
                (Content::B, Encoding::Binary | Encoding::Ascii) => {}
                (_, Encoding::Binary) => {
                    return Err(format!("field {i}: binary encoding is only valid for b"))
                }
                _ => {}
            }
            match fs.length {
                Length::LlVar(m) if m > 99 => {
                    return Err(format!("field {i}: LLVAR max {m} exceeds 99"))
                }
                Length::LllVar(m) if m > 999 => {
                    return Err(format!("field {i}: LLLVAR max {m} exceeds 999"))
                }
                Length::Fixed(0) => return Err(format!("field {i}: zero fixed length")),
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_profiles_validate() {
        for s in [
            Spec::v1987_ascii(),
            Spec::v1987_bcd(),
            Spec::v1987_text(),
            Spec::v1993_ascii(),
        ] {
            s.validate().unwrap();
            for n in 2..=128u8 {
                assert!(s.field(n).is_some(), "{} missing field {n}", s.name);
            }
        }
    }

    #[test]
    fn validate_rejects_bcd_alphanumeric() {
        let mut s = Spec::v1987_ascii();
        s.set_field(
            37,
            FieldSpec {
                name: "bad",
                content: Content::An,
                length: Length::Fixed(12),
                encoding: Encoding::Bcd,
                prefix: PrefixEncoding::Ascii,
            },
        );
        assert!(s.validate().is_err());
    }
}
