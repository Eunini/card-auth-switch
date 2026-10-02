//! Property tests: encode/decode round trips for every built-in profile, and
//! "never panics" guarantees for arbitrary and mutated input.

use iso8583::spec::{Content, FieldSpec, Length};
use iso8583::tlv::{self, Tlv};
use iso8583::{Message, Mti, Spec};
use proptest::prelude::*;
use proptest::sample::subsequence;

fn charset(content: Content) -> Vec<u8> {
    let mut v = Vec::new();
    match content {
        Content::N => v.extend(b'0'..=b'9'),
        Content::A => {
            v.extend(b'a'..=b'z');
            v.extend(b'A'..=b'Z');
            v.push(b' ');
        }
        Content::An => {
            v.extend(b'a'..=b'z');
            v.extend(b'A'..=b'Z');
            v.extend(b'0'..=b'9');
            v.push(b' ');
        }
        Content::Ans => v.extend(0x20u8..=0x7E),
        Content::Ns => v.extend((0x20u8..=0x7E).filter(|c| !c.is_ascii_alphabetic())),
        Content::Z => {
            v.extend(b'0'..=b'9');
            v.push(b'=');
        }
        Content::XN | Content::B => {}
    }
    v
}

fn value_strategy(fs: FieldSpec) -> BoxedStrategy<Vec<u8>> {
    let len: BoxedStrategy<usize> = match fs.length {
        Length::Fixed(l) => Just(l).boxed(),
        Length::LlVar(m) | Length::LllVar(m) => prop_oneof![
            8 => 0..=m.min(48),
            1 => Just(m),
            1 => Just(0usize),
        ]
        .boxed(),
    };
    match fs.content {
        Content::B => len
            .prop_flat_map(|l| proptest::collection::vec(any::<u8>(), l))
            .boxed(),
        Content::XN => len
            .prop_flat_map(|l| {
                (
                    prop_oneof![Just(b'C'), Just(b'D')],
                    proptest::collection::vec(b'0'..=b'9', l.saturating_sub(1)),
                )
            })
            .prop_map(|(s, mut d)| {
                d.insert(0, s);
                d
            })
            .boxed(),
        c => {
            let cs = charset(c);
            len.prop_flat_map(move |l| {
                proptest::collection::vec(proptest::sample::select(cs.clone()), l)
            })
            .boxed()
        }
    }
}

fn message_strategy(spec: Spec) -> impl Strategy<Value = Message> {
    let fields: Vec<u8> = (2..=128u8).filter(|&n| n != 65).collect();
    let version = spec.version.mti_digit() as u8;
    (
        proptest::collection::vec(b'0'..=b'9', 3),
        subsequence(fields, 0..=24),
    )
        .prop_flat_map(move |(mti_tail, chosen)| {
            let strategies: Vec<BoxedStrategy<(u8, Vec<u8>)>> = chosen
                .into_iter()
                .map(|n| {
                    value_strategy(*spec.field(n).unwrap())
                        .prop_map(move |v| (n, v))
                        .boxed()
                })
                .collect();
            let mut mti = vec![version];
            mti.extend(mti_tail);
            (Just(mti), strategies)
        })
        .prop_map(|(mti, kvs)| {
            let mut m = Message::new(Mti::from_bytes(&mti).unwrap());
            for (n, v) in kvs {
                m.set(n, v);
            }
            m
        })
}

fn profiles() -> Vec<Spec> {
    vec![
        Spec::v1987_ascii(),
        Spec::v1987_bcd(),
        Spec::v1987_text(),
        Spec::v1993_ascii(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn round_trip_1987_ascii(m in message_strategy(Spec::v1987_ascii())) {
        let spec = Spec::v1987_ascii();
        let bytes = m.encode(&spec).unwrap();
        prop_assert_eq!(Message::decode(&spec, &bytes).unwrap(), m);
    }

    #[test]
    fn round_trip_1987_bcd(m in message_strategy(Spec::v1987_bcd())) {
        let spec = Spec::v1987_bcd();
        let bytes = m.encode(&spec).unwrap();
        prop_assert_eq!(Message::decode(&spec, &bytes).unwrap(), m);
    }

    #[test]
    fn round_trip_1987_text(m in message_strategy(Spec::v1987_text())) {
        let spec = Spec::v1987_text();
        let bytes = m.encode(&spec).unwrap();
        prop_assert_eq!(Message::decode(&spec, &bytes).unwrap(), m);
    }

    #[test]
    fn round_trip_1993(m in message_strategy(Spec::v1993_ascii())) {
        let spec = Spec::v1993_ascii();
        let bytes = m.encode(&spec).unwrap();
        prop_assert_eq!(Message::decode(&spec, &bytes).unwrap(), m);
    }

    /// Arbitrary bytes never panic; anything that decodes re-encodes to a
    /// message that decodes to the same value (canonical form).
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        for spec in profiles() {
            if let Ok(m) = Message::decode(&spec, &bytes) {
                let again = m.encode(&spec).unwrap();
                prop_assert_eq!(Message::decode(&spec, &again).unwrap(), m);
            }
        }
    }

    /// Bytes that start with a plausible header reach the field decoders.
    #[test]
    fn plausible_header_never_panics(
        bitmap in any::<[u8; 16]>(),
        body in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        for spec in profiles() {
            let mut b = Vec::new();
            match spec.mti_encoding {
                iso8583::spec::MtiEncoding::Ascii => b.extend_from_slice(if spec.version == iso8583::spec::Version::V1987 { b"0100" } else { b"1100" }),
                iso8583::spec::MtiEncoding::Bcd => b.extend_from_slice(&[0x01, 0x00]),
            }
            b.extend_from_slice(&bitmap);
            b.extend_from_slice(&body);
            let _ = Message::decode(&spec, &b);
        }
    }

    /// Valid messages with a single corrupted byte or truncation never panic.
    #[test]
    fn mutated_messages_never_panic(
        m in message_strategy(Spec::v1987_ascii()),
        pos in any::<prop::sample::Index>(),
        val in any::<u8>(),
        cut in any::<prop::sample::Index>(),
    ) {
        let spec = Spec::v1987_ascii();
        let mut bytes = m.encode(&spec).unwrap();
        let i = pos.index(bytes.len());
        bytes[i] = val;
        let _ = Message::decode(&spec, &bytes);
        let c = cut.index(bytes.len());
        let _ = Message::decode(&spec, &bytes[..c]);
    }

    #[test]
    fn tlv_round_trip(items in proptest::collection::vec(tlv_strategy(), 0..12)) {
        let enc = tlv::encode(&items);
        prop_assert_eq!(tlv::parse(&enc).unwrap(), items);
    }

    #[test]
    fn tlv_arbitrary_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(list) = tlv::parse(&bytes) {
            for t in &list {
                if t.is_constructed() { let _ = t.children(); }
            }
        }
    }
}

/// Valid BER-TLV tags: 1 byte (low 5 bits != 11111), or 2-3 bytes with
/// continuation bits set correctly. Tag 0x00 is padding, so excluded.
fn tlv_strategy() -> impl Strategy<Value = Tlv> {
    let one = (1u8..=0xFF)
        .prop_filter("not multi-byte", |b| b & 0x1F != 0x1F)
        .prop_map(|b| b as u32);
    let two = (any::<u8>(), 0u8..0x80).prop_map(|(a, b)| (((a | 0x1F) as u32) << 8) | b as u32);
    let three = (any::<u8>(), 0x80u8..=0xFF, 0u8..0x80)
        .prop_map(|(a, b, c)| (((a | 0x1F) as u32) << 16) | ((b as u32) << 8) | c as u32);
    (
        prop_oneof![one, two, three],
        proptest::collection::vec(any::<u8>(), 0..300),
    )
        .prop_map(|(tag, value)| Tlv { tag, value })
}
