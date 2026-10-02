//! Command execution and TCP server.

use crate::keyblock::Lmk;
use crate::proto::*;
use cardcrypto::emv::{arpc_method1, arpc_method2, Cvn};
use cardcrypto::{des3, pin, pinblock, CryptoError};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use zeroize::Zeroizing;

pub struct Hsm {
    lmk: Lmk,
    /// Models the physical "authorized state" needed for key ceremonies.
    authorized: bool,
}

fn hx<const N: usize>(s: &str, what: &str) -> Result<[u8; N], HsmError> {
    let v = hex::decode(s).map_err(|_| HsmError::Malformed(format!("{what} is not hex")))?;
    v.try_into()
        .map_err(|_| HsmError::Malformed(format!("{what} must be {N} bytes")))
}

fn data_err(e: CryptoError) -> HsmError {
    match e {
        CryptoError::PinBlockFormat(m) => HsmError::PinBlockFormat(m.into()),
        other => HsmError::Data(other.to_string()),
    }
}

impl Hsm {
    pub fn new(lmk: Lmk, authorized: bool) -> Self {
        Self { lmk, authorized }
    }

    fn key(&self, kt: KeyType, block: &str) -> Result<Zeroizing<[u8; 16]>, HsmError> {
        self.lmk.unwrap(kt, block)
    }

    fn clear_pin(
        &self,
        zpk: &str,
        pin_block: &str,
        pan: &str,
    ) -> Result<Zeroizing<String>, HsmError> {
        let zpk = self.key(KeyType::Zpk, zpk)?;
        let pb: [u8; 8] = hx(pin_block, "pin_block")?;
        pinblock::decrypt_iso0(&zpk, &pb, pan)
            .map(Zeroizing::new)
            .map_err(data_err)
    }

    pub fn execute(&self, cmd: Command) -> Result<Reply, HsmError> {
        match cmd {
            Command::Echo { data } => Ok(Reply::Echo { data }),
            Command::Diagnostics => Ok(Reply::Diagnostics {
                lmk_kcv: self.lmk.kcv().to_string(),
                firmware: concat!("card-auth-switch simulated HSM ", env!("CARGO_PKG_VERSION"))
                    .to_string(),
            }),
            Command::GenerateKey { key_type } => {
                let mut k = Zeroizing::new([0u8; 16]);
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), k.as_mut());
                des3::adjust_parity(k.as_mut());
                Ok(self.key_reply(key_type, &k))
            }
            Command::FormKeyFromComponents {
                key_type,
                components,
            } => {
                if !self.authorized {
                    return Err(HsmError::NotPermitted(
                        "key ceremony requires authorized state".into(),
                    ));
                }
                if components.len() < 2 {
                    return Err(HsmError::Malformed("need at least 2 components".into()));
                }
                let mut k = Zeroizing::new([0u8; 16]);
                for c in &components {
                    let part: Zeroizing<[u8; 16]> = Zeroizing::new(hx(c, "component")?);
                    for i in 0..16 {
                        k[i] ^= part[i];
                    }
                }
                des3::adjust_parity(k.as_mut());
                Ok(self.key_reply(key_type, &k))
            }
            Command::ImportKey {
                key_type,
                zmk,
                key_under_zmk,
            } => {
                if key_type == KeyType::Zmk {
                    return Err(HsmError::NotPermitted(
                        "ZMK cannot be imported under a ZMK".into(),
                    ));
                }
                let zmk = self.key(KeyType::Zmk, &zmk)?;
                let enc: [u8; 16] = hx(&key_under_zmk, "key_under_zmk")?;
                let mut k = Zeroizing::new([0u8; 16]);
                k[..8].copy_from_slice(&des3::tdes_decrypt(&zmk, enc[..8].try_into().expect("8")));
                k[8..].copy_from_slice(&des3::tdes_decrypt(&zmk, enc[8..].try_into().expect("8")));
                Ok(self.key_reply(key_type, &k))
            }
            Command::KeyCheckValue { key_type, key } => {
                let k = self.key(key_type, &key)?;
                Ok(Reply::Kcv {
                    kcv: hex::encode_upper(des3::kcv(&k)),
                })
            }
            Command::VerifyPinPvv {
                zpk,
                pvk,
                pin_block,
                pan,
                pvki,
                pvv,
            } => {
                let clear = self.clear_pin(&zpk, &pin_block, &pan)?;
                let pvk = self.key(KeyType::Pvk, &pvk)?;
                if clear.len() != 4 {
                    // PVV is defined over 4-digit PINs; longer PINs cannot match.
                    return Ok(Reply::Verified { ok: false });
                }
                let ok = pin::verify_pvv(&pvk, pvki, &clear, &pan, &pvv).map_err(data_err)?;
                Ok(Reply::Verified { ok })
            }
            Command::VerifyPinIbm3624 {
                zpk,
                pvk,
                pin_block,
                pan,
                offset,
                decimalisation_table,
                pan_offset,
                pan_length,
            } => {
                let clear = self.clear_pin(&zpk, &pin_block, &pan)?;
                let pvk = self.key(KeyType::Pvk, &pvk)?;
                let p = pin::Ibm3624 {
                    decimalisation_table,
                    pan_offset,
                    pan_length,
                    pad: 'F',
                };
                if clear.len() != offset.len() {
                    return Ok(Reply::Verified { ok: false });
                }
                let expected = Zeroizing::new(p.derive_pin(&pvk, &pan, &offset).map_err(data_err)?);
                Ok(Reply::Verified {
                    ok: cardcrypto::ct_eq(expected.as_bytes(), clear.as_bytes()),
                })
            }
            Command::TranslatePin {
                src_zpk,
                dst_zpk,
                pin_block,
                pan,
            } => {
                let clear = self.clear_pin(&src_zpk, &pin_block, &pan)?;
                let dst = self.key(KeyType::Zpk, &dst_zpk)?;
                let out = pinblock::encrypt_iso0(&dst, &clear, &pan).map_err(data_err)?;
                Ok(Reply::PinBlock {
                    pin_block: hex::encode_upper(out),
                })
            }
            Command::GeneratePvv {
                zpk,
                pvk,
                pin_block,
                pan,
                pvki,
            } => {
                let clear = self.clear_pin(&zpk, &pin_block, &pan)?;
                let pvk = self.key(KeyType::Pvk, &pvk)?;
                let pvv = pin::visa_pvv(&pvk, pvki, &clear, &pan).map_err(data_err)?;
                Ok(Reply::Pvv { pvv })
            }
            Command::GenerateCvv {
                cvk,
                pan,
                expiry,
                service_code,
            } => {
                let cvk = self.key(KeyType::Cvk, &cvk)?;
                let cvv =
                    cardcrypto::cvv::cvv(&cvk, &pan, &expiry, &service_code).map_err(data_err)?;
                Ok(Reply::Cvv { cvv })
            }
            Command::VerifyCvv {
                cvk,
                pan,
                expiry,
                service_code,
                cvv,
            } => {
                let cvk = self.key(KeyType::Cvk, &cvk)?;
                let ok = cardcrypto::cvv::verify_cvv(&cvk, &pan, &expiry, &service_code, &cvv)
                    .map_err(data_err)?;
                Ok(Reply::Verified { ok })
            }
            Command::VerifyArqc {
                imk_ac,
                cvn,
                pan,
                psn,
                atc,
                data,
                arqc,
                arpc,
            } => {
                let cvn = Cvn::from_code(cvn)
                    .ok_or_else(|| HsmError::Data(format!("unsupported CVN {cvn}")))?;
                let imk = self.key(KeyType::ImkAc, &imk_ac)?;
                let atc: [u8; 2] = hx(&atc, "atc")?;
                let arqc: [u8; 8] = hx(&arqc, "arqc")?;
                let data = hex::decode(&data).map_err(|_| HsmError::Malformed("data".into()))?;
                if data.len() > 256 {
                    return Err(HsmError::Malformed("data too long".into()));
                }
                let mk = Zeroizing::new(cvn.icc_mk(&imk, &pan, &psn).map_err(data_err)?);
                let sk = Zeroizing::new(cvn.ac_key(&mk, atc));
                let expected = cardcrypto::emv::generate_ac(&sk, &data, cvn.padding());
                if !cardcrypto::ct_eq(&expected, &arqc) {
                    return Ok(Reply::Arqc {
                        ok: false,
                        tag91: None,
                    });
                }
                let tag91 = match arpc {
                    None => None,
                    Some(ArpcMethod::Method1 { arc }) => {
                        let arc: [u8; 2] = hx(&arc, "arc")?;
                        let a = arpc_method1(&sk, &arqc, &arc);
                        Some(hex::encode_upper([&a[..], &arc[..]].concat()))
                    }
                    Some(ArpcMethod::Method2 { csu, prop }) => {
                        let csu: [u8; 4] = hx(&csu, "csu")?;
                        let prop =
                            hex::decode(&prop).map_err(|_| HsmError::Malformed("prop".into()))?;
                        let a = arpc_method2(&sk, &arqc, &csu, &prop).map_err(data_err)?;
                        Some(hex::encode_upper([&a[..], &csu[..], &prop[..]].concat()))
                    }
                };
                Ok(Reply::Arqc { ok: true, tag91 })
            }
        }
    }

    fn key_reply(&self, kt: KeyType, k: &[u8; 16]) -> Reply {
        Reply::Key {
            key_block: self.lmk.wrap(kt, k),
            kcv: hex::encode_upper(des3::kcv(k)),
        }
    }
}

pub fn codec() -> tokio_util::codec::LengthDelimitedCodec {
    tokio_util::codec::LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(u16::MAX as usize)
        .new_codec()
}

pub async fn serve(listener: TcpListener, hsm: Arc<Hsm>) -> std::io::Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let hsm = hsm.clone();
        tokio::spawn(async move {
            tracing::debug!(%peer, "hsm client connected");
            handle(sock, hsm).await;
            tracing::debug!(%peer, "hsm client disconnected");
        });
    }
}

async fn handle(sock: TcpStream, hsm: Arc<Hsm>) {
    let (mut sink, mut stream) = Framed::new(sock, codec()).split();
    let (tx, mut rx) = mpsc::channel::<bytes::Bytes>(1024);
    let writer = tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            if sink.send(b).await.is_err() {
                break;
            }
        }
    });
    while let Some(Ok(frame)) = stream.next().await {
        let tx = tx.clone();
        let hsm = hsm.clone();
        // Each command is independent; run them concurrently and let the
        // request id correlate responses.
        tokio::spawn(async move {
            let resp = match serde_json::from_slice::<Request>(&frame) {
                Ok(req) => {
                    let name = req.cmd.name();
                    let result = hsm.execute(req.cmd);
                    if let Err(e) = &result {
                        tracing::debug!(cmd = name, error = %e, "command failed");
                    }
                    Response { id: req.id, result }
                }
                Err(e) => Response {
                    id: 0,
                    result: Err(HsmError::Malformed(e.to_string())),
                },
            };
            if let Ok(b) = serde_json::to_vec(&resp) {
                let _ = tx.send(b.into()).await;
            }
        });
    }
    drop(tx);
    let _ = writer.await;
}
