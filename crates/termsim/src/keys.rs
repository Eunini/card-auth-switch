use serde::Deserialize;

/// Clear *public test* keys (config/test-keys.toml). The simulator plays
/// the card personalisation bureau and the acquirer's PIN pad, which is
/// why it holds clear keys; the switch does not.
#[derive(Debug, Clone, Deserialize)]
pub struct TestKeys {
    pub zpk: String,
    pub zpk_issuer: String,
    pub pvk: String,
    pub pvki: u8,
    pub cvk: String,
    pub imk_ac: String,
    pub pan_hmac: String,
}

impl TestKeys {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }

    pub fn key(h: &str) -> [u8; 16] {
        hex::decode(h)
            .ok()
            .and_then(|v| v.try_into().ok())
            .expect("test key must be 16 bytes hex")
    }
}
