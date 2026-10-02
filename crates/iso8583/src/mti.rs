use crate::error::{Error, Result};
use std::fmt;

/// Message Type Indicator: version, class, function, origin.
///
/// `0100` = 1987 / authorization / request / acquirer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mti([u8; 4]);

impl Mti {
    pub const AUTH_REQUEST: Mti = Mti(*b"0100");
    pub const AUTH_RESPONSE: Mti = Mti(*b"0110");
    pub const AUTH_ADVICE: Mti = Mti(*b"0120");
    pub const AUTH_ADVICE_RESPONSE: Mti = Mti(*b"0130");
    pub const FIN_REQUEST: Mti = Mti(*b"0200");
    pub const FIN_RESPONSE: Mti = Mti(*b"0210");
    pub const FIN_ADVICE: Mti = Mti(*b"0220");
    pub const REVERSAL_REQUEST: Mti = Mti(*b"0400");
    pub const REVERSAL_REQUEST_REPEAT: Mti = Mti(*b"0401");
    pub const REVERSAL_RESPONSE: Mti = Mti(*b"0410");
    pub const REVERSAL_ADVICE: Mti = Mti(*b"0420");
    pub const REVERSAL_ADVICE_REPEAT: Mti = Mti(*b"0421");
    pub const REVERSAL_ADVICE_RESPONSE: Mti = Mti(*b"0430");
    pub const NETWORK_REQUEST: Mti = Mti(*b"0800");
    pub const NETWORK_RESPONSE: Mti = Mti(*b"0810");

    pub fn new(s: &str) -> Result<Self> {
        Self::from_bytes(s.as_bytes())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 4 || !b.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidMti(String::from_utf8_lossy(b).into_owned()));
        }
        Ok(Mti([b[0], b[1], b[2], b[3]]))
    }

    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        // Invariant: always four ASCII digits.
        std::str::from_utf8(&self.0).unwrap_or("????")
    }

    pub fn version(&self) -> char {
        self.0[0] as char
    }
    /// Message class: 1 authorization, 2 financial, 4 reversal, 8 network management.
    pub fn class(&self) -> u8 {
        self.0[1] - b'0'
    }
    /// Message function: 0 request, 1 response, 2 advice, 3 advice response.
    pub fn function(&self) -> u8 {
        self.0[2] - b'0'
    }
    /// Origin: 0 acquirer, 1 acquirer repeat, 2 issuer, 3 issuer repeat, ...
    pub fn origin(&self) -> u8 {
        self.0[3] - b'0'
    }

    pub fn is_repeat(&self) -> bool {
        self.origin() % 2 == 1
    }

    pub fn is_request_or_advice(&self) -> bool {
        matches!(self.function(), 0 | 2)
    }

    /// Same message with the repeat flag cleared (`0401` -> `0400`).
    pub fn without_repeat(&self) -> Mti {
        let mut m = self.0;
        if self.is_repeat() {
            m[3] -= 1;
        }
        Mti(m)
    }

    /// The MTI of the response to this request/advice (`0100` -> `0110`,
    /// `0421` -> `0430`). `None` for responses.
    pub fn response(&self) -> Option<Mti> {
        if !self.is_request_or_advice() {
            return None;
        }
        let mut m = self.without_repeat().0;
        m[2] += 1;
        Some(Mti(m))
    }
}

impl fmt::Display for Mti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Mti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mti({})", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_mapping() {
        let cases = [
            ("0100", Some("0110")),
            ("0120", Some("0130")),
            ("0200", Some("0210")),
            ("0400", Some("0410")),
            ("0401", Some("0410")),
            ("0420", Some("0430")),
            ("0421", Some("0430")),
            ("0800", Some("0810")),
            ("0110", None),
            ("1100", Some("1110")),
        ];
        for (req, resp) in cases {
            let m = Mti::new(req).unwrap();
            assert_eq!(
                m.response().map(|r| r.to_string()),
                resp.map(String::from),
                "{req}"
            );
        }
    }

    #[test]
    fn rejects_bad_mti() {
        assert!(Mti::new("01A0").is_err());
        assert!(Mti::new("010").is_err());
        assert!(Mti::new("").is_err());
    }

    #[test]
    fn parts() {
        let m = Mti::new("0421").unwrap();
        assert_eq!(
            (m.version(), m.class(), m.function(), m.origin()),
            ('0', 4, 2, 1)
        );
        assert!(m.is_repeat());
        assert_eq!(m.without_repeat(), Mti::REVERSAL_ADVICE);
    }
}
