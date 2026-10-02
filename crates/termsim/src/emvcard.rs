//! EMV card emulator: keeps the ICC master key and ATC, produces field 55
//! with an ARQC, and checks the issuer's ARPC (issuer authentication).

use crate::cards::CardSecret;
use crate::keys::TestKeys;
use cardcrypto::emv::{card_verify_arpc, ArqcData, Cvn};
use cardcrypto::Key16;
use iso8583::tlv::Tlv;

pub struct EmvCard {
    pub secret: CardSecret,
    pub cvn: Cvn,
    icc_mk: Key16,
}

#[derive(Debug, Clone)]
pub struct Cryptogram {
    pub tlvs: Vec<Tlv>,
    pub arqc: [u8; 8],
    pub atc: [u8; 2],
}

pub fn bcd_n12(v: i64) -> [u8; 6] {
    let s = format!("{v:012}");
    let mut o = [0u8; 6];
    for (i, p) in s.as_bytes().chunks(2).enumerate() {
        o[i] = ((p[0] - b'0') << 4) | (p[1] - b'0');
    }
    o
}

fn bcd2(s: &str) -> [u8; 2] {
    let v = hex::decode(format!("{s:0>4}")).expect("numeric");
    [v[0], v[1]]
}

impl EmvCard {
    /// Personalise: derive the card's MK-AC from the issuer master key.
    pub fn personalise(secret: CardSecret, keys: &TestKeys) -> anyhow::Result<Self> {
        let cvn = Cvn::from_code(secret.cvn).ok_or_else(|| anyhow::anyhow!("unsupported CVN"))?;
        let icc_mk = cvn.icc_mk(&TestKeys::key(&keys.imk_ac), &secret.pan, &secret.psn)?;
        Ok(Self {
            secret,
            cvn,
            icc_mk,
        })
    }

    /// GENERATE AC (first), requesting an ARQC.
    pub fn generate_arqc(
        &mut self,
        amount_minor: i64,
        currency: &str,
        yymmdd: &str,
        txn_type: u8,
        unpredictable: [u8; 4],
    ) -> anyhow::Result<Cryptogram> {
        self.secret.atc = self.secret.atc.wrapping_add(1);
        let atc = self.secret.atc.to_be_bytes();
        let iad = match self.cvn {
            Cvn::Visa10 => vec![0x06, 0x01, 0x0A, 0x03, 0xA0, 0x00, 0x00],
            Cvn::Visa18 => vec![0x06, 0x01, 0x12, 0x03, 0xA0, 0x00, 0x00],
        };
        let date: [u8; 3] = hex::decode(yymmdd)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("date"))?;
        let d = ArqcData {
            amount_authorised: bcd_n12(amount_minor),
            amount_other: [0; 6],
            terminal_country: bcd2("840"),
            tvr: [0; 5],
            currency: bcd2(currency),
            txn_date: date,
            txn_type,
            unpredictable,
            aip: [0x18, 0x00],
            atc,
            iad: iad.clone(),
        };
        let arqc = self.cvn.generate_arqc(&self.icc_mk, &d)?;
        let psn: u8 = self.secret.psn.parse().unwrap_or(0);
        let tlvs = vec![
            Tlv::new(0x9F26, arqc.to_vec()),
            Tlv::new(0x9F27, vec![0x80]),
            Tlv::new(0x9F10, iad),
            Tlv::new(0x9F37, unpredictable.to_vec()),
            Tlv::new(0x9F36, atc.to_vec()),
            Tlv::new(0x95, d.tvr.to_vec()),
            Tlv::new(0x9A, date.to_vec()),
            Tlv::new(0x9C, vec![txn_type]),
            Tlv::new(0x9F02, d.amount_authorised.to_vec()),
            Tlv::new(0x5F2A, d.currency.to_vec()),
            Tlv::new(0x82, d.aip.to_vec()),
            Tlv::new(0x9F1A, d.terminal_country.to_vec()),
            Tlv::new(0x9F03, d.amount_other.to_vec()),
            Tlv::new(0x5F34, vec![((psn / 10) << 4) | (psn % 10)]),
            Tlv::new(0x84, vec![0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]),
            Tlv::new(0x9F33, vec![0xE0, 0xF8, 0xC8]),
            Tlv::new(0x9F34, vec![0x42, 0x03, 0x00]),
        ];
        Ok(Cryptogram { tlvs, arqc, atc })
    }

    /// EXTERNAL AUTHENTICATE: does the issuer's tag 91 prove it holds the key?
    pub fn verify_arpc(&self, c: &Cryptogram, tag91: &[u8]) -> bool {
        card_verify_arpc(self.cvn, &self.icc_mk, c.atc, &c.arqc, tag91)
    }
}
