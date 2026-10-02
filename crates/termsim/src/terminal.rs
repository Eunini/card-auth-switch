//! Acquirer terminal simulator: builds realistic ISO 8583:1987 requests.

use crate::emvcard::{Cryptogram, EmvCard};
use crate::keys::TestKeys;
use chrono::{Datelike, Timelike, Utc};
use iso8583::{pad_ans, pad_n, tlv, Message, Mti};
use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// Contact chip (F22 = 051: chip, PIN entry capable)
    Chip,
    /// Contactless chip (F22 = 071)
    Contactless,
    /// Magnetic stripe, full track 2 (F22 = 901)
    Magstripe,
}

#[derive(Debug, Clone)]
pub struct TxnOpts {
    pub entry: Entry,
    /// PIN typed by the cardholder (None = no PIN / signature / CDCVM).
    pub pin: Option<String>,
    pub cash: bool,
    pub mcc: String,
    /// Corrupt the ARQC after the card produced it (tamper test).
    pub tamper_arqc: bool,
}

impl TxnOpts {
    pub fn chip_pin(pin: &str) -> Self {
        Self {
            entry: Entry::Chip,
            pin: Some(pin.to_string()),
            cash: false,
            mcc: "5411".into(),
            tamper_arqc: false,
        }
    }
}

pub struct Terminal {
    pub tid: String,
    pub mid: String,
    pub location: String,
    pub acquirer_id: String,
    stan: u32,
    zpk: [u8; 16],
    pvki: u8,
}

/// A request plus what the card produced for it (to check the ARPC).
pub struct Built {
    pub msg: Message,
    pub cryptogram: Option<Cryptogram>,
}

impl Terminal {
    pub fn new(tid: &str, keys: &TestKeys) -> Self {
        Self {
            tid: pad_ans(tid, 8),
            mid: pad_ans("MERCH000000001", 15),
            location: pad_ans("CORNER GROCERY         SPRINGFIELD  US", 40),
            acquirer_id: "41000001".into(),
            stan: rand::thread_rng().gen_range(1..900_000),
            zpk: TestKeys::key(&keys.zpk),
            pvki: keys.pvki,
        }
    }

    pub fn with_stan(mut self, stan: u32) -> Self {
        self.stan = stan;
        self
    }

    fn next_stan(&mut self) -> String {
        self.stan = self.stan % 999_999 + 1;
        pad_n(self.stan as u64, 6)
    }

    fn header(&mut self, mti: Mti) -> (Message, String) {
        let now = Utc::now();
        let stan = self.next_stan();
        let mut m = Message::new(mti);
        m.set(7, now.format("%m%d%H%M%S").to_string())
            .set(11, stan.clone());
        (m, stan)
    }

    pub fn sign_on(&mut self) -> Message {
        self.header(Mti::NETWORK_REQUEST).0.with(70, "001")
    }

    pub fn echo(&mut self) -> Message {
        self.header(Mti::NETWORK_REQUEST).0.with(70, "301")
    }

    pub fn sign_off(&mut self) -> Message {
        self.header(Mti::NETWORK_REQUEST).0.with(70, "002")
    }

    /// 0100 (purchase, dual message) or 0200 (cash, single message).
    pub fn auth(
        &mut self,
        card: &mut EmvCard,
        amount_minor: i64,
        o: &TxnOpts,
    ) -> anyhow::Result<Built> {
        let mti = if o.cash {
            Mti::FIN_REQUEST
        } else {
            Mti::AUTH_REQUEST
        };
        let (mut m, stan) = self.header(mti);
        let now = Utc::now();
        let rrn = format!(
            "{}{:03}{:02}{}",
            now.year() % 10,
            now.ordinal(),
            now.hour(),
            stan
        );
        let s = &card.secret;
        m.set(2, s.pan.clone())
            .set(3, if o.cash { "010000" } else { "000000" })
            .set(4, pad_n(amount_minor as u64, 12))
            .set(12, now.format("%H%M%S").to_string())
            .set(13, now.format("%m%d").to_string())
            .set(14, s.expiry.clone())
            .set(
                18,
                if o.cash {
                    "6011".to_string()
                } else {
                    o.mcc.clone()
                },
            )
            .set(25, "00")
            .set(32, self.acquirer_id.clone())
            .set(37, rrn)
            .set(41, self.tid.clone())
            .set(42, self.mid.clone())
            .set(43, self.location.clone())
            .set(49, "840");
        let mut cryptogram = None;
        match o.entry {
            Entry::Chip | Entry::Contactless => {
                m.set(22, if o.entry == Entry::Chip { "051" } else { "071" });
                m.set(23, format!("0{}", s.psn));
                m.set(35, s.track2(self.pvki, true));
                let un: [u8; 4] = rand::thread_rng().gen();
                let mut c = card.generate_arqc(
                    amount_minor,
                    "840",
                    &now.format("%y%m%d").to_string(),
                    if o.cash { 0x01 } else { 0x00 },
                    un,
                )?;
                if o.tamper_arqc {
                    c.arqc[7] ^= 0x01;
                    c.tlvs[0] = tlv::Tlv::new(0x9F26, c.arqc.to_vec());
                }
                m.set(55, tlv::encode(&c.tlvs));
                cryptogram = Some(c);
            }
            Entry::Magstripe => {
                m.set(22, "901");
                m.set(35, s.track2(self.pvki, false));
            }
        }
        if let Some(pin) = &o.pin {
            let pb = cardcrypto::pinblock::encrypt_iso0(&self.zpk, pin, &card.secret.pan)?;
            m.set(52, pb.to_vec());
            // F22 position 3 = 1: terminal can accept PINs
        }
        Ok(Built { msg: m, cryptogram })
    }

    /// 0400 reversal request / 0420 reversal advice for `original`.
    /// `replacement` = amount that remains authorised (partial reversal).
    pub fn reversal(
        &mut self,
        original: &Message,
        replacement: Option<i64>,
        advice: bool,
    ) -> Message {
        let (mut m, _) = self.header(if advice {
            Mti::REVERSAL_ADVICE
        } else {
            Mti::REVERSAL_REQUEST
        });
        for f in [2u8, 3, 4, 32, 37, 41, 42, 49] {
            if let Some(v) = original.get(f) {
                m.set(f, v.to_vec());
            }
        }
        let f90 = format!(
            "{}{}{}{:0>11}{:0>11}",
            original.mti,
            original.get_str(11).unwrap_or("000000"),
            original.get_str(7).unwrap_or("0000000000"),
            original.get_str(32).unwrap_or(""),
            ""
        );
        m.set(90, f90);
        if let Some(r) = replacement {
            m.set(
                95,
                format!(
                    "{}{}C00000000C00000000",
                    pad_n(r as u64, 12),
                    pad_n(r as u64, 12)
                ),
            );
        }
        m
    }

    /// Mark a reversal as a repeat (0401 / 0421), same STAN.
    pub fn as_repeat(m: &Message) -> Message {
        let mut r = m.clone();
        let mut mti = *m.mti.as_bytes();
        mti[3] = b'1';
        r.mti = Mti::from_bytes(&mti).expect("valid mti");
        r
    }
}
