//! ISO/IEC 9797-1 MAC algorithm 3 ("retail MAC", ANSI X9.19): single-DES
//! CBC with K1 over all blocks, then decrypt with K2 and encrypt with K1 on
//! the final block. This is the MAC EMV uses for application cryptograms
//! with double-length DES keys.

use crate::des3::{des_decrypt, des_encrypt, xor8};
use crate::Key16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    /// Method 1: zero-pad to a block boundary (no padding if aligned).
    /// Used by Visa CVN 10.
    Method1,
    /// Method 2: append 0x80 then zero-pad. Used by EMV common core / CVN 18.
    Method2,
}

pub fn pad(data: &[u8], p: Padding) -> Vec<u8> {
    let mut v = data.to_vec();
    match p {
        Padding::Method1 => {
            if v.is_empty() {
                v.resize(8, 0);
            }
            while !v.len().is_multiple_of(8) {
                v.push(0);
            }
        }
        Padding::Method2 => {
            v.push(0x80);
            while !v.len().is_multiple_of(8) {
                v.push(0);
            }
        }
    }
    v
}

pub fn iso9797_alg3(key: &Key16, data: &[u8], p: Padding) -> [u8; 8] {
    let k1: [u8; 8] = key[..8].try_into().expect("8");
    let k2: [u8; 8] = key[8..].try_into().expect("8");
    let padded = pad(data, p);
    let mut h = [0u8; 8];
    for block in padded.chunks(8) {
        h = des_encrypt(&k1, &xor8(&h, block.try_into().expect("8")));
    }
    des_encrypt(&k1, &des_decrypt(&k2, &h))
}
