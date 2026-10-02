//! Message model and the spec-driven encoder/decoder.

use crate::error::{Error, Result};
use crate::mti::Mti;
use crate::reader::Reader;
use crate::spec::{
    BitmapEncoding, Content, Encoding, FieldSpec, Length, MtiEncoding, PrefixEncoding, Spec,
};
use crate::tlv;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// An ISO 8583 message: an MTI plus a sparse set of data elements 2..=128.
///
/// Values are stored in their *logical* form: ASCII characters for
/// n/a/an/ans/z/x+n content and raw bytes for `b` content. The wire form
/// (BCD, hex, prefixes) is applied only by [`Message::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub mti: Mti,
    fields: BTreeMap<u8, Vec<u8>>,
}

impl Message {
    pub fn new(mti: Mti) -> Self {
        Self {
            mti,
            fields: BTreeMap::new(),
        }
    }

    /// Set a data element. Field 1 (secondary bitmap) and 65 (tertiary
    /// bitmap) are managed by the codec and cannot be set.
    pub fn set(&mut self, n: u8, value: impl Into<Vec<u8>>) -> &mut Self {
        assert!(
            (2..=128).contains(&n) && n != 65,
            "field {n} cannot be set directly"
        );
        self.fields.insert(n, value.into());
        self
    }

    pub fn with(mut self, n: u8, value: impl Into<Vec<u8>>) -> Self {
        self.set(n, value);
        self
    }

    pub fn get(&self, n: u8) -> Option<&[u8]> {
        self.fields.get(&n).map(Vec::as_slice)
    }

    /// Text view of a non-binary field.
    pub fn get_str(&self, n: u8) -> Option<&str> {
        self.get(n).and_then(|v| std::str::from_utf8(v).ok())
    }

    pub fn has(&self, n: u8) -> bool {
        self.fields.contains_key(&n)
    }

    pub fn remove(&mut self, n: u8) -> Option<Vec<u8>> {
        self.fields.remove(&n)
    }

    pub fn fields(&self) -> impl Iterator<Item = (u8, &[u8])> {
        self.fields.iter().map(|(k, v)| (*k, v.as_slice()))
    }

    /// Build a response skeleton: response MTI and the echo fields that a
    /// response must carry back unchanged.
    pub fn response_template(&self, echo: &[u8]) -> Option<Message> {
        let mut r = Message::new(self.mti.response()?);
        for &n in echo {
            if let Some(v) = self.get(n) {
                r.set(n, v.to_vec());
            }
        }
        Some(r)
    }

    pub fn encode(&self, spec: &Spec) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        encode_mti(&self.mti, spec, &mut out);

        let mut primary: u64 = 0;
        let mut secondary: u64 = 0;
        for &n in self.fields.keys() {
            if n <= 64 {
                primary |= 1u64 << (64 - n as u32);
            } else {
                secondary |= 1u64 << (128 - n as u32);
            }
        }
        if secondary != 0 {
            primary |= 1u64 << 63;
        }
        encode_bitmap(primary, spec.bitmap_encoding, &mut out);
        if secondary != 0 {
            encode_bitmap(secondary, spec.bitmap_encoding, &mut out);
        }

        for (&n, value) in &self.fields {
            let fs = spec.field(n).ok_or(Error::UndefinedField(n))?;
            encode_field(n, fs, value, &mut out)?;
        }
        Ok(out)
    }

    pub fn decode(spec: &Spec, data: &[u8]) -> Result<Message> {
        let mut r = Reader::new(data);
        let mti = decode_mti(spec, &mut r)?;
        if mti.version() != spec.version.mti_digit() {
            return Err(Error::MtiVersion {
                expected: spec.version.mti_digit(),
                found: mti.version(),
            });
        }
        let primary = decode_bitmap(spec.bitmap_encoding, &mut r)?;
        let secondary = if primary & (1u64 << 63) != 0 {
            let s = decode_bitmap(spec.bitmap_encoding, &mut r)?;
            if s & (1u64 << 63) != 0 {
                return Err(Error::TertiaryBitmap);
            }
            s
        } else {
            0
        };

        let mut msg = Message::new(mti);
        for n in 2u8..=128 {
            let set = if n <= 64 {
                primary & (1u64 << (64 - n as u32)) != 0
            } else {
                secondary & (1u64 << (128 - n as u32)) != 0
            };
            if !set {
                continue;
            }
            let fs = spec.field(n).ok_or(Error::UndefinedField(n))?;
            let v = decode_field(n, fs, &mut r)?;
            msg.fields.insert(n, v);
        }
        if r.remaining() != 0 {
            return Err(Error::TrailingBytes(r.remaining()));
        }
        Ok(msg)
    }

    /// Human-readable dump with sensitive data masked: PAN shows first 6 and
    /// last 4, track 2 is masked after the PAN, PIN blocks are redacted and
    /// field 55 is expanded into its EMV tags.
    pub fn describe(&self, spec: &Spec) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "MTI {}", self.mti);
        for (&n, v) in &self.fields {
            let name = spec.field(n).map(|f| f.name).unwrap_or("?");
            let shown = match n {
                2 => mask_pan(&String::from_utf8_lossy(v)),
                35 => {
                    let t = String::from_utf8_lossy(v);
                    let pan = t.split('=').next().unwrap_or("");
                    format!("{}=****", mask_pan(pan))
                }
                52 => "[PIN block redacted]".to_string(),
                55 => match tlv::parse(v) {
                    Ok(list) => list
                        .iter()
                        .map(|t| format!("{:X}={}", t.tag, hex_upper(&t.value)))
                        .collect::<Vec<_>>()
                        .join(" "),
                    Err(_) => hex_upper(v),
                },
                _ => match spec.field(n).map(|f| f.content) {
                    Some(Content::B) => hex_upper(v),
                    _ => String::from_utf8_lossy(v).into_owned(),
                },
            };
            let _ = writeln!(s, "  F{n:03} {name:<40} {shown}");
        }
        s
    }
}

pub fn mask_pan(pan: &str) -> String {
    if pan.len() < 13 {
        return "*".repeat(pan.len());
    }
    format!(
        "{}{}{}",
        &pan[..6],
        "*".repeat(pan.len() - 10),
        &pan[pan.len() - 4..]
    )
}

pub(crate) fn hex_upper(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 0xF) as usize] as char);
    }
    s
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

// ---------- MTI and bitmaps ----------

fn encode_mti(mti: &Mti, spec: &Spec, out: &mut Vec<u8>) {
    let b = mti.as_bytes();
    match spec.mti_encoding {
        MtiEncoding::Ascii => out.extend_from_slice(b),
        MtiEncoding::Bcd => {
            out.push(((b[0] - b'0') << 4) | (b[1] - b'0'));
            out.push(((b[2] - b'0') << 4) | (b[3] - b'0'));
        }
    }
}

fn decode_mti(spec: &Spec, r: &mut Reader<'_>) -> Result<Mti> {
    match spec.mti_encoding {
        MtiEncoding::Ascii => Mti::from_bytes(r.take(4, "MTI")?),
        MtiEncoding::Bcd => {
            let b = r.take(2, "MTI")?;
            let digits = unpack_bcd(b, 4, false).map_err(|_| Error::InvalidMti(hex_upper(b)))?;
            Mti::from_bytes(&digits)
        }
    }
}

fn encode_bitmap(bm: u64, enc: BitmapEncoding, out: &mut Vec<u8>) {
    match enc {
        BitmapEncoding::Binary => out.extend_from_slice(&bm.to_be_bytes()),
        BitmapEncoding::Hex => out.extend_from_slice(hex_upper(&bm.to_be_bytes()).as_bytes()),
    }
}

fn decode_bitmap(enc: BitmapEncoding, r: &mut Reader<'_>) -> Result<u64> {
    match enc {
        BitmapEncoding::Binary => {
            let b = r.take(8, "bitmap")?;
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            Ok(u64::from_be_bytes(a))
        }
        BitmapEncoding::Hex => {
            let b = r.take(16, "bitmap")?;
            let mut v: u64 = 0;
            for &c in b {
                let d = hex_val(c).ok_or_else(|| Error::field(1, "bitmap is not hex"))?;
                v = (v << 4) | d as u64;
            }
            Ok(v)
        }
    }
}

// ---------- content validation ----------

fn content_ok(content: Content, v: &[u8]) -> bool {
    match content {
        Content::N => v.iter().all(u8::is_ascii_digit),
        Content::A => v.iter().all(|c| c.is_ascii_alphabetic() || *c == b' '),
        Content::An => v.iter().all(|c| c.is_ascii_alphanumeric() || *c == b' '),
        Content::Ans => v.iter().all(|c| (0x20..=0x7E).contains(c)),
        Content::Ns => v
            .iter()
            .all(|c| (0x20..=0x7E).contains(c) && !c.is_ascii_alphabetic()),
        Content::Z => v.iter().all(|c| c.is_ascii_digit() || *c == b'='),
        Content::XN => match v.split_first() {
            Some((s, rest)) => (*s == b'C' || *s == b'D') && rest.iter().all(u8::is_ascii_digit),
            None => false,
        },
        Content::B => true,
    }
}

// ---------- BCD ----------

/// Pack ASCII digits (and `=` as nibble D for track data) into BCD.
/// Odd-length numerics are left-padded with 0; track data (`z`) is
/// right-padded with F, matching common practice for PAN and track 2.
fn pack_bcd(v: &[u8], content: Content) -> Vec<u8> {
    let nib = |c: u8| if c == b'=' { 0xD } else { c - b'0' };
    let mut nibbles: Vec<u8> = Vec::with_capacity(v.len() + 1);
    let odd = v.len() % 2 == 1;
    if odd && content != Content::Z {
        nibbles.push(0);
    }
    nibbles.extend(v.iter().map(|&c| nib(c)));
    if odd && content == Content::Z {
        nibbles.push(0xF);
    }
    nibbles.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

fn unpack_bcd(b: &[u8], digits: usize, z: bool) -> std::result::Result<Vec<u8>, String> {
    let total = b.len() * 2;
    if digits > total {
        return Err("BCD shorter than declared length".into());
    }
    let skip_front = if z { 0 } else { total - digits };
    let mut out = Vec::with_capacity(digits);
    for i in skip_front..skip_front + digits {
        let byte = b[i / 2];
        let n = if i % 2 == 0 { byte >> 4 } else { byte & 0xF };
        let c = match n {
            0..=9 => b'0' + n,
            0xD if z => b'=',
            _ => return Err(format!("invalid BCD nibble {n:X}")),
        };
        out.push(c);
    }
    Ok(out)
}

// ---------- fields ----------

fn encode_field(n: u8, fs: &FieldSpec, value: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if !content_ok(fs.content, value) {
        return Err(Error::field(
            n,
            format!("value violates {:?} content rules", fs.content),
        ));
    }
    let len = value.len();
    match fs.length {
        Length::Fixed(l) if len != l => {
            return Err(Error::field(n, format!("length {len} != fixed length {l}")))
        }
        Length::LlVar(m) | Length::LllVar(m) if len > m => {
            return Err(Error::field(n, format!("length {len} exceeds max {m}")))
        }
        Length::LlVar(_) => write_prefix(len, 2, fs.prefix, out),
        Length::LllVar(_) => write_prefix(len, 3, fs.prefix, out),
        Length::Fixed(_) => {}
    }
    match (fs.content, fs.encoding) {
        (Content::B, Encoding::Ascii) => out.extend_from_slice(hex_upper(value).as_bytes()),
        (Content::N | Content::Z, Encoding::Bcd) => out.extend(pack_bcd(value, fs.content)),
        _ => out.extend_from_slice(value),
    }
    Ok(())
}

fn write_prefix(len: usize, digits: usize, enc: PrefixEncoding, out: &mut Vec<u8>) {
    match (enc, digits) {
        (PrefixEncoding::Ascii, 2) => out.extend_from_slice(format!("{len:02}").as_bytes()),
        (PrefixEncoding::Ascii, _) => out.extend_from_slice(format!("{len:03}").as_bytes()),
        (PrefixEncoding::Bcd, 2) => out.push((((len / 10) as u8) << 4) | (len % 10) as u8),
        (PrefixEncoding::Bcd, _) => {
            out.push((len / 100) as u8);
            out.push(((((len / 10) % 10) as u8) << 4) | (len % 10) as u8);
        }
    }
}

fn read_prefix(n: u8, digits: usize, enc: PrefixEncoding, r: &mut Reader<'_>) -> Result<usize> {
    let bad = || Error::field(n, "invalid length prefix");
    match enc {
        PrefixEncoding::Ascii => {
            let b = r.take(digits, "length prefix")?;
            if !b.iter().all(u8::is_ascii_digit) {
                return Err(bad());
            }
            Ok(b.iter().fold(0usize, |a, c| a * 10 + (c - b'0') as usize))
        }
        PrefixEncoding::Bcd => {
            let nbytes = digits.div_ceil(2);
            let b = r.take(nbytes, "length prefix")?;
            let d = unpack_bcd(b, digits, false).map_err(|_| bad())?;
            Ok(d.iter().fold(0usize, |a, c| a * 10 + (c - b'0') as usize))
        }
    }
}

fn decode_field(n: u8, fs: &FieldSpec, r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let len = match fs.length {
        Length::Fixed(l) => l,
        Length::LlVar(m) | Length::LllVar(m) => {
            let digits = if matches!(fs.length, Length::LlVar(_)) {
                2
            } else {
                3
            };
            let l = read_prefix(n, digits, fs.prefix, r)?;
            if l > m {
                return Err(Error::field(n, format!("length {l} exceeds max {m}")));
            }
            l
        }
    };
    let value = match (fs.content, fs.encoding) {
        (Content::B, Encoding::Ascii) => {
            let h = r.take(len * 2, "field data")?;
            let mut v = Vec::with_capacity(len);
            for p in h.chunks(2) {
                match (hex_val(p[0]), hex_val(p[1])) {
                    (Some(a), Some(b)) => v.push((a << 4) | b),
                    _ => return Err(Error::field(n, "invalid hex")),
                }
            }
            v
        }
        (Content::N | Content::Z, Encoding::Bcd) => {
            let b = r.take(len.div_ceil(2), "field data")?;
            unpack_bcd(b, len, fs.content == Content::Z).map_err(|e| Error::field(n, e))?
        }
        _ => r.take(len, "field data")?.to_vec(),
    };
    if !content_ok(fs.content, &value) {
        return Err(Error::field(
            n,
            format!("value violates {:?} content rules", fs.content),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Message {
        let mut m = Message::new(Mti::AUTH_REQUEST);
        m.set(2, "4761739001010010")
            .set(3, "000000")
            .set(4, "000000001500")
            .set(7, "1002143015")
            .set(11, "000123")
            .set(22, "051")
            .set(35, "4761739001010010=28122011234567890")
            .set(37, "627514000123")
            .set(41, "TERM0001")
            .set(49, "840")
            .set(52, vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
            .set(55, vec![0x9F, 0x36, 0x02, 0x00, 0x1C])
            .set(90, "010000012310021430150000000000100000000000");
        m
    }

    #[test]
    fn round_trip_all_profiles() {
        for spec in [Spec::v1987_ascii(), Spec::v1987_bcd(), Spec::v1987_text()] {
            let m = sample();
            let bytes = m.encode(&spec).unwrap();
            assert_eq!(Message::decode(&spec, &bytes).unwrap(), m, "{}", spec.name);
        }
    }

    #[test]
    fn ascii_layout_is_exact() {
        let spec = Spec::v1987_ascii();
        let mut m = Message::new(Mti::NETWORK_REQUEST);
        m.set(7, "1002143015").set(11, "000001").set(70, "301");
        let b = m.encode(&spec).unwrap();
        // MTI, primary bitmap with bits 1,7,11 set, secondary with bit 70.
        assert_eq!(&b[..4], b"0800");
        assert_eq!(&b[4..12], &[0x82, 0x20, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&b[12..20], &[0x04, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&b[20..], b"1002143015000001301");
    }

    #[test]
    fn bcd_layout_is_exact() {
        let spec = Spec::v1987_bcd();
        let mut m = Message::new(Mti::AUTH_REQUEST);
        m.set(2, "476173900101001") // 15 digits: odd -> left pad
            .set(22, "051")
            .set(35, "4761739001010010=281");
        let b = m.encode(&spec).unwrap();
        assert_eq!(&b[..2], &[0x01, 0x00]);
        let body = &b[10..];
        assert_eq!(
            &body[..9],
            &[0x15, 0x04, 0x76, 0x17, 0x39, 0x00, 0x10, 0x10, 0x01]
        );
        assert_eq!(&body[9..11], &[0x00, 0x51]);
        // track 2: 20 chars, '=' -> D, even so no pad
        assert_eq!(
            &body[11..],
            &[0x20, 0x47, 0x61, 0x73, 0x90, 0x01, 0x01, 0x00, 0x10, 0xD2, 0x81]
        );
    }

    #[test]
    fn rejects_bad_content_and_lengths() {
        let spec = Spec::v1987_ascii();
        let m = Message::new(Mti::AUTH_REQUEST).with(4, "12AB");
        assert!(m.encode(&spec).is_err());
        let m = Message::new(Mti::AUTH_REQUEST).with(2, "1".repeat(20));
        assert!(m.encode(&spec).is_err());
        let m = Message::new(Mti::AUTH_REQUEST).with(35, "4761=28ZZ");
        assert!(m.encode(&spec).is_err());
    }

    #[test]
    fn decode_errors_are_typed() {
        let spec = Spec::v1987_ascii();
        assert!(matches!(
            Message::decode(&spec, b"01"),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            Message::decode(&spec, b"0X00"),
            Err(Error::InvalidMti(_))
        ));
        assert!(matches!(
            Message::decode(&spec, b"1100\0\0\0\0\0\0\0\0"),
            Err(Error::MtiVersion { .. })
        ));
        let mut ok = sample().encode(&spec).unwrap();
        ok.push(b'X');
        assert_eq!(Message::decode(&spec, &ok), Err(Error::TrailingBytes(1)));
        // Tertiary bitmap
        let mut t = b"0100".to_vec();
        t.extend_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Message::decode(&spec, &t), Err(Error::TertiaryBitmap));
        // LLVAR prefix over max
        let mut p = b"0100".to_vec();
        p.extend_from_slice(&[0x40, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(b"20");
        p.extend_from_slice(&[b'1'; 20]);
        assert!(matches!(
            Message::decode(&spec, &p),
            Err(Error::Field { field: 2, .. })
        ));
    }

    #[test]
    fn v1993_profile_differs() {
        let spec = Spec::v1993_ascii();
        let mut m = Message::new(Mti::new("1100").unwrap());
        m.set(12, "261002143015").set(39, "000").set(24, "100");
        let b = m.encode(&spec).unwrap();
        assert_eq!(Message::decode(&spec, &b).unwrap(), m);
        // A 1987 response code (an2) is invalid in the 1993 action code slot.
        let bad = Message::new(Mti::new("1110").unwrap()).with(39, "00");
        assert!(bad.encode(&spec).is_err());
    }

    #[test]
    fn describe_masks_sensitive_fields() {
        let d = sample().describe(&Spec::v1987_ascii());
        assert!(d.contains("476173******0010"));
        assert!(!d.contains("4761739001010010"));
        assert!(d.contains("[PIN block redacted]"));
        assert!(d.contains("9F36=001C"));
    }

    #[test]
    fn response_template_echoes() {
        let r = sample().response_template(&[2, 11, 37, 41, 99]).unwrap();
        assert_eq!(r.mti, Mti::AUTH_RESPONSE);
        assert_eq!(r.get_str(11), Some("000123"));
        assert!(!r.has(4));
    }
}
