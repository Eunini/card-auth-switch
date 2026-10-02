//! End-to-end over TCP: client -> server -> crypto, using the pyemv CVN 18
//! vector so the HSM path is pinned to a published result.

use hsm::client::HsmClient;
use hsm::keyblock::Lmk;
use hsm::proto::*;
use hsm::server::{serve, Hsm};
use std::sync::Arc;
use std::time::Duration;

const LMK: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
const IMK: &str = "0123456789ABCDEFFEDCBA9876543210";

async fn start(authorized: bool) -> (String, Lmk) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(serve(
        l,
        Arc::new(Hsm::new(Lmk::from_hex(LMK).unwrap(), authorized)),
    ));
    (addr, Lmk::from_hex(LMK).unwrap())
}

fn k(h: &str) -> [u8; 16] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[tokio::test]
async fn pin_cvv_arqc_over_tcp() {
    let (addr, lmk) = start(false).await;
    let c = HsmClient::connect(&addr, 2, Duration::from_secs(2))
        .await
        .unwrap();

    let zpk_clear = k("1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A");
    let pvk_clear = k(IMK);
    let zpk = lmk.wrap(KeyType::Zpk, &zpk_clear);
    let pvk = lmk.wrap(KeyType::Pvk, &pvk_clear);

    // PIN 4524 on PAN 1122334455667788 has PVV 4021 with PVKI 3 (psec vector).
    let pan = "1122334455667788";
    let pb = cardcrypto::pinblock::encrypt_iso0(&zpk_clear, "4524", pan).unwrap();
    let verify = |pvv: &str, block: [u8; 8]| Command::VerifyPinPvv {
        zpk: zpk.clone(),
        pvk: pvk.clone(),
        pin_block: hex::encode_upper(block),
        pan: pan.into(),
        pvki: 3,
        pvv: pvv.into(),
    };
    assert_eq!(
        c.call(verify("4021", pb)).await.unwrap(),
        Reply::Verified { ok: true }
    );
    let wrong = cardcrypto::pinblock::encrypt_iso0(&zpk_clear, "4525", pan).unwrap();
    assert_eq!(
        c.call(verify("4021", wrong)).await.unwrap(),
        Reply::Verified { ok: false }
    );

    // Using the ZPK block where a PVK is expected is refused.
    let misuse = Command::VerifyPinPvv {
        zpk: zpk.clone(),
        pvk: zpk.clone(),
        pin_block: hex::encode_upper(pb),
        pan: pan.into(),
        pvki: 3,
        pvv: "4021".into(),
    };
    assert!(matches!(
        c.call(misuse).await,
        Err(hsm::client::ClientError::Hsm(HsmError::KeyUsage { .. }))
    ));

    // PIN translation ZPK1 -> ZPK2 keeps the PIN.
    let zpk2_clear = k("4A4A4A4A4A4A4A4A5B5B5B5B5B5B5B5B");
    let zpk2 = lmk.wrap(KeyType::Zpk, &zpk2_clear);
    let Reply::PinBlock { pin_block } = c
        .call(Command::TranslatePin {
            src_zpk: zpk.clone(),
            dst_zpk: zpk2,
            pin_block: hex::encode_upper(pb),
            pan: pan.into(),
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    let out: [u8; 8] = hex::decode(pin_block).unwrap().try_into().unwrap();
    assert_eq!(
        cardcrypto::pinblock::decrypt_iso0(&zpk2_clear, &out, pan).unwrap(),
        "4524"
    );

    // CVV classic vector
    let cvk = lmk.wrap(KeyType::Cvk, &k(IMK));
    let r = c
        .call(Command::VerifyCvv {
            cvk,
            pan: "4123456789012345".into(),
            expiry: "8701".into(),
            service_code: "101".into(),
            cvv: "561".into(),
        })
        .await
        .unwrap();
    assert_eq!(r, Reply::Verified { ok: true });

    // ARQC CVN 18 (pyemv tests/test_cvn_hsm.py) -> ARPC method 2 9AF514C1
    let imk = lmk.wrap(KeyType::ImkAc, &k(IMK));
    let data = concat!(
        "000000004000",
        "000000000000",
        "0124",
        "8000048000",
        "0124",
        "191105",
        "01",
        "52BF4585",
        "1800",
        "001C",
        "06011203A0B800"
    );
    let cmd = |arqc: &str| Command::VerifyArqc {
        imk_ac: imk.clone(),
        cvn: 18,
        pan: "1234567890123456".into(),
        psn: "00".into(),
        atc: "001C".into(),
        data: data.into(),
        arqc: arqc.into(),
        arpc: Some(ArpcMethod::Method2 {
            csu: "00000000".into(),
            prop: String::new(),
        }),
    };
    assert_eq!(
        c.call(cmd("7A788EA6B8A3E733")).await.unwrap(),
        Reply::Arqc {
            ok: true,
            tag91: Some("9AF514C100000000".into())
        }
    );
    assert_eq!(
        c.call(cmd("7A788EA6B8A3E734")).await.unwrap(),
        Reply::Arqc {
            ok: false,
            tag91: None
        }
    );
}

#[tokio::test]
async fn key_ceremony_requires_authorized_state_and_import_works() {
    let (addr, _) = start(false).await;
    let c = HsmClient::connect(&addr, 1, Duration::from_secs(2))
        .await
        .unwrap();
    let form = Command::FormKeyFromComponents {
        key_type: KeyType::Zmk,
        components: vec!["11".repeat(16), "22".repeat(16)],
    };
    assert!(matches!(
        c.call(form.clone()).await,
        Err(hsm::client::ClientError::Hsm(HsmError::NotPermitted(_)))
    ));

    let (addr, _) = start(true).await;
    let c = HsmClient::connect(&addr, 1, Duration::from_secs(2))
        .await
        .unwrap();
    let Reply::Key {
        key_block: zmk,
        kcv,
    } = c.call(form).await.unwrap()
    else {
        panic!()
    };
    // 11..^22.. = 33.., with odd parity adjustment -> 32..
    let zmk_clear = k(&"32".repeat(16));
    assert_eq!(kcv, hex::encode_upper(cardcrypto::des3::kcv(&zmk_clear)));

    // Import a ZPK sent by a partner encrypted under the ZMK.
    let zpk_clear = k("1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A");
    let enc = cardcrypto::des3::tdes_ecb_encrypt(&zmk_clear, &zpk_clear).unwrap();
    let Reply::Key { kcv, .. } = c
        .call(Command::ImportKey {
            key_type: KeyType::Zpk,
            zmk,
            key_under_zmk: hex::encode_upper(enc),
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(kcv, hex::encode_upper(cardcrypto::des3::kcv(&zpk_clear)));
}

#[tokio::test]
async fn many_concurrent_requests_are_correlated() {
    let (addr, _) = start(false).await;
    let c = Arc::new(
        HsmClient::connect(&addr, 2, Duration::from_secs(5))
            .await
            .unwrap(),
    );
    let mut hs = Vec::new();
    for i in 0..500 {
        let c = c.clone();
        hs.push(tokio::spawn(async move {
            let d = format!("m{i}");
            assert_eq!(
                c.call(Command::Echo { data: d.clone() }).await.unwrap(),
                Reply::Echo { data: d }
            );
        }));
    }
    for h in hs {
        h.await.unwrap();
    }
}
