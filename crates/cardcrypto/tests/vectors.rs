//! Published test vectors.
//!
//! Sources (all public; keys below are well-known *test* keys):
//! * [PYEMV]   pyemv by K. Novichikhin, https://github.com/knovichikhin/pyemv
//!   - `tests/test_kd_hsm.py`, `tests/test_cvn_hsm.py` (the `_hsm` suites,
//!     whose expected values the project states were cross-checked on a
//!     hardware HSM), plus the module docstrings in `pyemv/kd.py` and
//!     `pyemv/ac.py`.
//! * [PSEC]    psec by K. Novichikhin, https://github.com/knovichikhin/psec
//!   - `tests/test_pinblock.py`, `tests/test_pin.py`, `tests/test_cvv.py` and
//!     docstrings in `psec/pin.py`, `psec/pinblock.py`, `psec/cvv.py`.
//! * [CVV-CLASSIC] the long-standing Visa CVV worked example (PAN
//!   4123456789012345, expiry 8701, service code 101, CVK
//!   0123456789ABCDEF/FEDCBA9876543210 -> 561), reproduced in many HSM
//!   vendor manuals and payment-crypto references.

use cardcrypto::des3::kcv;
use cardcrypto::emv::*;
use cardcrypto::mac::Padding;
use cardcrypto::pin::{visa_pvv, Ibm3624};
use cardcrypto::{cvv, pinblock};

fn k(h: &str) -> [u8; 16] {
    hex::decode(h).unwrap().try_into().unwrap()
}
fn up(b: &[u8]) -> String {
    hex::encode_upper(b)
}

const IMK: &str = "0123456789ABCDEFFEDCBA9876543210";

// ---------------- EMV key derivation ----------------

#[test]
fn pyemv_kd_docstring_option_a() {
    // [PYEMV] pyemv/kd.py module + derive_icc_mk_a docstrings
    let imk = k(IMK);
    assert_eq!(
        up(&derive_icc_mk_a(&imk, "99012345678901234", "45").unwrap()),
        "67F8292358083E5EA7AB7FDA58D53B6B"
    );
    assert_eq!(
        up(&derive_icc_mk_a(&imk, "12345678901234567", "01").unwrap()),
        "73AD54688CEF2934B0979857E3C719F1"
    );
}

#[test]
fn pyemv_kd_docstring_option_b() {
    // [PYEMV] derive_icc_mk_b docstring (19-digit PAN path uses SHA-1)
    let imk = k(IMK);
    assert_eq!(
        up(&derive_icc_mk_b(&imk, "12345678901234567", "01").unwrap()),
        "AD406D7F6D7570916D75E5DCAB8CF737"
    );
}

#[test]
fn pyemv_common_session_key_docstring() {
    // [PYEMV] derive_common_sk docstring
    let sk = derive_common_sk(
        &k(IMK),
        &hex::decode("001C000000000000").unwrap().try_into().unwrap(),
    );
    assert_eq!(up(&sk), "E9FB384AF807B940FEDCEA613461B0C4");
}

#[test]
fn pyemv_hsm_option_a_csk_arqc_arpc() {
    // [PYEMV] tests/test_kd_hsm.py::test_derive_icc_mk_a_psn
    let imk = k(IMK);
    assert_eq!(up(&kcv(&imk)[..2]), "08D7");
    let mk = derive_icc_mk_a(&imk, "12345678901234567", "45").unwrap();
    assert_eq!(up(&kcv(&mk)[..2]), "FF08");
    let sk = derive_common_sk(
        &mk,
        &hex::decode("1234567890123456").unwrap().try_into().unwrap(),
    );
    assert_eq!(up(&kcv(&sk)[..2]), "DF82");
    let data = hex::decode("0123456789ABCDEF0123456789ABCDEF").unwrap();
    let arqc = generate_ac(&sk, &data, Padding::Method2);
    assert_eq!(up(&arqc), "19C1FBC83EBDC0D5");
    assert_eq!(up(&arpc_method1(&mk, &arqc, &[0, 0])), "78A372523FA35A03");
}

// ---------------- AC / ARPC primitives ----------------

#[test]
fn pyemv_ac_docstrings() {
    // [PYEMV] pyemv/ac.py module docstring
    let sk = k("29B33180E567CE38EA4CBC9D753B0E61");
    let arqc = generate_ac(
        &sk,
        &hex::decode("0123456789ABCDEF0123456789ABCDEF").unwrap(),
        Padding::Method2,
    );
    assert_eq!(up(&arqc), "FA624250B008B59A");
    assert_eq!(up(&arpc_method1(&sk, &arqc, &[0, 0])), "45D4255EEF10C920");
    assert_eq!(
        up(&arpc_method2(&sk, &arqc, &[0; 4], &[]).unwrap()),
        "CB56FA40"
    );

    // [PYEMV] generate_ac / generate_arpc_1 / generate_arpc_2 docstrings
    let sk = k("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB");
    let data = hex::decode(concat!(
        "000000002000",
        "000000000000",
        "0124",
        "0000008000",
        "0124",
        "110309",
        "00",
        "3804823E",
        "5800",
        "0001"
    ))
    .unwrap();
    assert_eq!(
        up(&generate_ac(&sk, &data, Padding::Method2)),
        "3B76CF10FECD8789"
    );
    let arqc: [u8; 8] = hex::decode("1234567890ABCDEF").unwrap().try_into().unwrap();
    assert_eq!(up(&arpc_method1(&sk, &arqc, &[0, 0])), "F5E6F44147E2F1B0");
    assert_eq!(
        up(&arpc_method2(&sk, &arqc, &[0; 4], &[]).unwrap()),
        "9308BEBC"
    );
}

fn cvn_txn(iad: &str) -> ArqcData {
    // [PYEMV] tests/test_cvn_hsm.py transaction data
    ArqcData {
        amount_authorised: hex::decode("000000004000").unwrap().try_into().unwrap(),
        amount_other: [0; 6],
        terminal_country: [0x01, 0x24],
        tvr: hex::decode("8000048000").unwrap().try_into().unwrap(),
        currency: [0x01, 0x24],
        txn_date: [0x19, 0x11, 0x05],
        txn_type: 0x01,
        unpredictable: hex::decode("52BF4585").unwrap().try_into().unwrap(),
        aip: [0x18, 0x00],
        atc: [0x00, 0x1C],
        iad: hex::decode(iad).unwrap(),
    }
}

#[test]
fn pyemv_hsm_visa_cvn10() {
    // [PYEMV] tests/test_cvn_hsm.py::test_visa_cvn10
    let mk = Cvn::Visa10
        .icc_mk(&k(IMK), "1234567890123456", "00")
        .unwrap();
    assert_eq!(up(&kcv(&mk)[..2]), "BAB0");
    // CVR 03A06010 sits at IAD bytes 3..7 for CVN 10
    let d = cvn_txn("06010A03A06010");
    assert_eq!(Cvn::from_iad(&d.iad), Some(Cvn::Visa10));
    let arqc = Cvn::Visa10.generate_arqc(&mk, &d).unwrap();
    assert_eq!(up(&arqc), "29CCA15AE665FA2E");
    let arpc = arpc_method1(&Cvn::Visa10.ac_key(&mk, d.atc), &arqc, b"00");
    assert_eq!(up(&arpc), "28993816AFAE4AEB");
}

#[test]
fn pyemv_hsm_visa_cvn18() {
    // [PYEMV] tests/test_cvn_hsm.py::test_visa_cvn18
    let mk = Cvn::Visa18
        .icc_mk(&k(IMK), "1234567890123456", "00")
        .unwrap();
    assert_eq!(up(&kcv(&mk)[..2]), "BAB0");
    let d = cvn_txn("06011203A0B800");
    assert_eq!(Cvn::from_iad(&d.iad), Some(Cvn::Visa18));
    let sk = Cvn::Visa18.ac_key(&mk, d.atc);
    assert_eq!(up(&kcv(&sk)[..2]), "22C8");
    let arqc = Cvn::Visa18.generate_arqc(&mk, &d).unwrap();
    assert_eq!(up(&arqc), "7A788EA6B8A3E733");
    assert_eq!(
        up(&arpc_method2(&sk, &arqc, &[0; 4], &[]).unwrap()),
        "9AF514C1"
    );
}

#[test]
fn card_side_arpc_verification() {
    let mk = Cvn::Visa18
        .icc_mk(&k(IMK), "1234567890123456", "00")
        .unwrap();
    let d = cvn_txn("06011203A0B800");
    let arqc = Cvn::Visa18.generate_arqc(&mk, &d).unwrap();
    let tag91 = hex::decode("9AF514C100000000").unwrap();
    assert!(card_verify_arpc(Cvn::Visa18, &mk, d.atc, &arqc, &tag91));
    let mut bad = tag91.clone();
    bad[0] ^= 1;
    assert!(!card_verify_arpc(Cvn::Visa18, &mk, d.atc, &arqc, &bad));
}

// ---------------- PIN ----------------

#[test]
fn psec_iso0_pin_blocks() {
    // [PSEC] tests/test_pinblock.py and encode_pinblock_iso_0 docstring
    let cases = [
        ("1234", "5555555551234567", "041261AAAAEDCBA9"),
        ("123456789", "5555555551234567", "091261032D8DCBA9"),
        ("1234567890", "5555555551234567", "0A1261032D82CBA9"),
        ("123456789012", "5555555551234567", "0C1261032D8226A9"),
        ("1234", "5544332211009966", "041277CDDEEFF669"),
    ];
    for (pin, pan, block) in cases {
        let b = pinblock::encode_iso0(pin, pan).unwrap();
        assert_eq!(up(&b), block);
        assert_eq!(pinblock::decode_iso0(&b, pan).unwrap(), pin);
    }
}

#[test]
fn psec_iso0_rejects_malformed() {
    // [PSEC] tests/test_pinblock.py::test_decode_pinblock_iso_0_exception
    let pan = "5555555551234567";
    for bad in [
        "241261AAAAEDCBA9",
        "0F1261AAAAEDCBA9",
        "021261AAAAEDCBA9",
        "041261AAAAEDCBAA",
        "051261AAAAEDCBA9",
    ] {
        let b: [u8; 8] = hex::decode(bad).unwrap().try_into().unwrap();
        assert!(pinblock::decode_iso0(&b, pan).is_err(), "{bad}");
    }
}

#[test]
fn psec_visa_pvv() {
    // [PSEC] tests/test_pin.py::test_generate_visa_pvv and docstring
    let pvk = k(IMK);
    let cases = [
        (1, "4524", "1122334455667788", "8523"),
        (2, "1912", "1122334455667788", "3244"),
        (1, "0570", "1122334455667718", "3144"),
        (1, "8299", "1122334455667708", "4422"),
        (3, "4524", "1122334455667788", "4021"),
    ];
    for (pvki, pin, pan, pvv) in cases {
        assert_eq!(visa_pvv(&pvk, pvki, pin, pan).unwrap(), pvv, "{pin}");
    }
}

#[test]
fn psec_ibm3624() {
    // [PSEC] tests/test_pin.py ibm3624 pin/offset cases (16-digit validation data, pad F)
    let pvk = k(IMK);
    let p = Ibm3624 {
        decimalisation_table: "1234567890123456".into(),
        pan_offset: 0,
        pan_length: 16,
        pad: 'F',
    };
    let pan = "1122334455667788";
    for (offset, pin) in [
        ("0000", "4524"),
        ("1111", "5635"),
        ("6586", "0000"),
        ("7697", "1111"),
        ("7710", "1234"),
    ] {
        assert_eq!(p.derive_pin(&pvk, pan, offset).unwrap(), pin);
        assert_eq!(p.offset_for(&pvk, pan, pin).unwrap(), offset);
    }
    let p14 = Ibm3624 {
        pan_length: 14,
        ..p
    };
    assert_eq!(p14.derive_pin(&pvk, pan, "0000").unwrap(), "5518");
}

// ---------------- CVV ----------------

#[test]
fn cvv_vectors() {
    let cvk = k("0123456789ABCDEFFEDCBA9876543210");
    // [CVV-CLASSIC]
    assert_eq!(
        cvv::cvv(&cvk, "4123456789012345", "8701", "101").unwrap(),
        "561"
    );
    // [PSEC] generate_cvv docstring
    assert_eq!(
        cvv::cvv(&cvk, "1234567890123456", "9912", "220").unwrap(),
        "170"
    );
    // [PSEC] tests/test_cvv.py::test_generate_cvv
    let cvk2 = k("99999999999999998888888888888888");
    assert_eq!(
        cvv::cvv(&cvk2, "2222222222222222", "3333", "111").unwrap(),
        "361"
    );
}

#[test]
fn kcv_of_well_known_test_key() {
    // 0123456789ABCDEF FEDCBA9876543210 has the widely quoted KCV 08D7B4.
    assert_eq!(up(&kcv(&k(IMK))), "08D7B4");
}
