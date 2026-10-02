//! Thin wrappers around RustCrypto DES / two-key 3DES (EDE2).

use crate::{Key16, Result};
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::{Des, TdesEde2};

pub fn tdes_encrypt(key: &Key16, block: &[u8; 8]) -> [u8; 8] {
    let c = TdesEde2::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    c.encrypt_block(&mut b);
    b.into()
}

pub fn tdes_decrypt(key: &Key16, block: &[u8; 8]) -> [u8; 8] {
    let c = TdesEde2::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    c.decrypt_block(&mut b);
    b.into()
}

pub fn des_encrypt(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let c = Des::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    c.encrypt_block(&mut b);
    b.into()
}

pub fn des_decrypt(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let c = Des::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    c.decrypt_block(&mut b);
    b.into()
}

/// 3DES-ECB over a multiple of 8 bytes.
pub fn tdes_ecb_encrypt(key: &Key16, data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(8) {
        return Err(crate::CryptoError::Input(
            "ECB data must be a multiple of 8 bytes",
        ));
    }
    Ok(data
        .chunks(8)
        .flat_map(|c| tdes_encrypt(key, c.try_into().expect("chunk of 8")))
        .collect())
}

/// Set odd parity on every byte, as DES keys require by convention.
pub fn adjust_parity(key: &mut [u8]) {
    for b in key.iter_mut() {
        let ones = (*b >> 1).count_ones();
        *b = (*b & 0xFE) | if ones % 2 == 0 { 1 } else { 0 };
    }
}

/// Key check value: first 3 bytes of 3DES(key, 0000000000000000).
pub fn kcv(key: &Key16) -> [u8; 3] {
    let e = tdes_encrypt(key, &[0u8; 8]);
    [e[0], e[1], e[2]]
}

pub fn xor8(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = a[i] ^ b[i];
    }
    o
}
