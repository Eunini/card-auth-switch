//! BER-TLV as used by EMV (field 55): multi-byte tags, short and long form
//! lengths, constructed templates.

use crate::error::{Error, Result};
use crate::reader::Reader;

/// One TLV. `tag` holds the raw tag bytes big-endian (e.g. `0x9F26`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub tag: u32,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(tag: u32, value: impl Into<Vec<u8>>) -> Self {
        Self {
            tag,
            value: value.into(),
        }
    }

    /// Constructed tags (bit 6 of the first tag byte) contain nested TLVs.
    pub fn is_constructed(&self) -> bool {
        first_tag_byte(self.tag) & 0x20 != 0
    }

    pub fn children(&self) -> Result<Vec<Tlv>> {
        if !self.is_constructed() {
            return Err(Error::Tlv(format!("tag {:X} is primitive", self.tag)));
        }
        parse(&self.value)
    }
}

fn tag_len(tag: u32) -> usize {
    match tag {
        0..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFF_FFFF => 3,
        _ => 4,
    }
}

fn first_tag_byte(tag: u32) -> u8 {
    (tag >> ((tag_len(tag) - 1) * 8)) as u8
}

/// Max EMV tag length we accept (1 leading + 3 subsequent bytes).
const MAX_TAG_BYTES: usize = 4;
/// Upper bound for a single value; field 55 is far smaller than this.
const MAX_VALUE_LEN: usize = 0xFFFF;

fn read_tag(r: &mut Reader<'_>) -> Result<u32> {
    let b0 = r.take_u8("TLV tag")?;
    let mut tag = b0 as u32;
    if b0 & 0x1F == 0x1F {
        let mut n = 1;
        loop {
            let b = r.take_u8("TLV tag")?;
            n += 1;
            if n > MAX_TAG_BYTES {
                return Err(Error::Tlv("tag longer than 4 bytes".into()));
            }
            tag = (tag << 8) | b as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    Ok(tag)
}

fn read_len(r: &mut Reader<'_>) -> Result<usize> {
    let b0 = r.take_u8("TLV length")?;
    if b0 & 0x80 == 0 {
        return Ok(b0 as usize);
    }
    let n = (b0 & 0x7F) as usize;
    if n == 0 || n > 3 {
        return Err(Error::Tlv(format!("unsupported length form {b0:02X}")));
    }
    let bytes = r.take(n, "TLV length")?;
    let len = bytes.iter().fold(0usize, |a, &b| (a << 8) | b as usize);
    if len > MAX_VALUE_LEN {
        return Err(Error::Tlv(format!("length {len} too large")));
    }
    Ok(len)
}

/// Parse a flat sequence of TLVs. `00` padding bytes between objects are
/// skipped, as EMV permits.
pub fn parse(data: &[u8]) -> Result<Vec<Tlv>> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let tag = read_tag(&mut r)?;
        if tag == 0x00 {
            continue;
        }
        let len = read_len(&mut r)?;
        let value = r.take(len, "TLV value")?.to_vec();
        out.push(Tlv { tag, value });
    }
    Ok(out)
}

pub fn encode(list: &[Tlv]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in list {
        let n = tag_len(t.tag);
        for i in (0..n).rev() {
            out.push((t.tag >> (i * 8)) as u8);
        }
        let len = t.value.len();
        match len {
            0..=0x7F => out.push(len as u8),
            0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
            0x100..=0xFFFF => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
            _ => out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(&t.value);
    }
    out
}

/// First value for `tag` in a flat list.
pub fn find(list: &[Tlv], tag: u32) -> Option<&[u8]> {
    list.iter()
        .find(|t| t.tag == tag)
        .map(|t| t.value.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_field_55() {
        // 9F26 (ARQC) 8 bytes, 9F27 1 byte, 82 2 bytes, 9F36 2 bytes, 5F2A 2 bytes
        let raw = [
            0x9F, 0x26, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x9F, 0x27, 0x01, 0x80, 0x82, 0x02, 0x18,
            0x00, 0x9F, 0x36, 0x02, 0x00, 0x1C, 0x5F, 0x2A, 0x02, 0x08, 0x40,
        ];
        let l = parse(&raw).unwrap();
        assert_eq!(l.len(), 5);
        assert_eq!(find(&l, 0x9F26), Some(&[1, 2, 3, 4, 5, 6, 7, 8][..]));
        assert_eq!(find(&l, 0x82), Some(&[0x18, 0x00][..]));
        assert_eq!(find(&l, 0x5F2A), Some(&[0x08, 0x40][..]));
        assert_eq!(encode(&l), raw);
    }

    #[test]
    fn long_form_lengths_and_constructed() {
        let inner = encode(&[Tlv::new(0x5A, vec![0x47; 8]), Tlv::new(0x9F02, vec![0; 6])]);
        let big = Tlv::new(0x70, inner.clone());
        assert!(big.is_constructed());
        assert_eq!(big.children().unwrap().len(), 2);
        let v200 = Tlv::new(0xDF8101, vec![0xAB; 200]);
        let enc = encode(std::slice::from_ref(&v200));
        assert_eq!(&enc[..5], &[0xDF, 0x81, 0x01, 0x81, 200]);
        assert_eq!(parse(&enc).unwrap(), vec![v200]);
    }

    #[test]
    fn malformed() {
        assert!(parse(&[0x9F]).is_err());
        assert!(parse(&[0x9F, 0x26, 0x08, 1, 2]).is_err());
        assert!(parse(&[0x82, 0x85, 0, 0, 0, 0, 1]).is_err());
        assert!(parse(&[0x9F, 0xFF, 0xFF, 0xFF, 0x01, 0x00]).is_err());
        // padding is skipped
        assert_eq!(
            parse(&[0x00, 0x00, 0x82, 0x00]).unwrap(),
            vec![Tlv::new(0x82, vec![])]
        );
    }
}
