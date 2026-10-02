//! LMK-wrapped key blocks.
//!
//! Format (ASCII): `K1` | usage (2, TR-31 code) | nonce (24 hex) | AES-256-GCM
//! ciphertext + tag of the 16-byte 3DES key (64 hex). The header (`K1` +
//! usage) is authenticated as associated data, so changing the declared
//! usage of a block makes it fail to unwrap. This mirrors the intent of
//! ANSI X9.143 / TR-31 key blocks (binding a key to its usage), but is a
//! simplified, non-standard format.

use crate::proto::{HsmError, KeyType};
use aes::cipher::{BlockEncrypt, KeyInit as _};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

pub struct Lmk {
    cipher: Aes256Gcm,
    kcv: String,
}

impl Lmk {
    pub fn from_hex(h: &str) -> Result<Lmk, String> {
        let bytes = Zeroizing::new(hex::decode(h.trim()).map_err(|e| e.to_string())?);
        if bytes.len() != 32 {
            return Err("LMK must be 32 bytes (AES-256)".into());
        }
        let aes = aes::Aes256::new_from_slice(&bytes).map_err(|e| e.to_string())?;
        let mut z = aes::Block::default();
        aes.encrypt_block(&mut z);
        Ok(Lmk {
            cipher: Aes256Gcm::new_from_slice(&bytes).map_err(|e| e.to_string())?,
            kcv: hex::encode_upper(&z[..3]),
        })
    }

    pub fn kcv(&self) -> &str {
        &self.kcv
    }

    pub fn wrap(&self, kt: KeyType, clear: &[u8; 16]) -> String {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let header = format!("K1{}", kt.usage_code());
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: clear,
                    aad: header.as_bytes(),
                },
            )
            .expect("AES-GCM encryption cannot fail for 16-byte input");
        format!(
            "{header}{}{}",
            hex::encode_upper(nonce),
            hex::encode_upper(ct)
        )
    }

    pub fn unwrap(&self, expected: KeyType, block: &str) -> Result<Zeroizing<[u8; 16]>, HsmError> {
        if block.len() != 92 || !block.is_ascii() || !block.starts_with("K1") {
            return Err(HsmError::KeyBlock("not a K1 key block".into()));
        }
        let usage = &block[2..4];
        if KeyType::from_usage_code(usage) != Some(expected) {
            return Err(HsmError::KeyUsage {
                expected: expected.usage_code().into(),
            });
        }
        let nonce =
            hex::decode(&block[4..28]).map_err(|_| HsmError::KeyBlock("bad nonce".into()))?;
        let ct =
            hex::decode(&block[28..]).map_err(|_| HsmError::KeyBlock("bad ciphertext".into()))?;
        let pt = Zeroizing::new(
            self.cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &block.as_bytes()[..4],
                    },
                )
                .map_err(|_| {
                    HsmError::KeyBlock("authentication failed (wrong LMK or tampered)".into())
                })?,
        );
        let mut k = Zeroizing::new([0u8; 16]);
        k.copy_from_slice(&pt);
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LMK: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

    #[test]
    fn wrap_unwrap() {
        let l = Lmk::from_hex(LMK).unwrap();
        let k = [7u8; 16];
        let b = l.wrap(KeyType::Zpk, &k);
        assert_eq!(b.len(), 92);
        assert_eq!(*l.unwrap(KeyType::Zpk, &b).unwrap(), k);
    }

    #[test]
    fn usage_is_enforced_and_authenticated() {
        let l = Lmk::from_hex(LMK).unwrap();
        let b = l.wrap(KeyType::Zpk, &[1u8; 16]);
        // Asking for a PVK with a ZPK block is refused.
        assert!(matches!(
            l.unwrap(KeyType::Pvk, &b),
            Err(HsmError::KeyUsage { .. })
        ));
        // Relabelling the header to V2 breaks the GCM tag.
        let forged = format!("K1V2{}", &b[4..]);
        assert!(matches!(
            l.unwrap(KeyType::Pvk, &forged),
            Err(HsmError::KeyBlock(_))
        ));
        // Different LMK cannot unwrap.
        let other = Lmk::from_hex(&"11".repeat(32)).unwrap();
        assert!(other.unwrap(KeyType::Zpk, &b).is_err());
        // Garbage
        assert!(l.unwrap(KeyType::Zpk, "K1P0zz").is_err());
    }
}
