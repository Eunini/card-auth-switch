use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: String,
    #[serde(default = "d_idle")]
    pub idle_timeout_secs: u64,
    #[serde(default = "d_inflight")]
    pub max_in_flight_per_conn: usize,
    pub hsm_addr: String,
    #[serde(default = "d_pool")]
    pub hsm_pool: usize,
    #[serde(default = "d_hsm_timeout")]
    pub hsm_timeout_ms: u64,
    pub issuer_url: String,
    pub issuer_timeout_ms: u64,
    #[serde(default = "d_refresh")]
    pub card_refresh_secs: u64,
    pub card_snapshot_file: String,
    pub stip_journal: String,
    pub pan_hmac_key: String,
    pub keys: Keys,
    pub stand_in: StandIn,
    pub circuit: Circuit,
}

/// LMK-wrapped key blocks; opaque to the switch.
#[derive(Debug, Clone, Deserialize)]
pub struct Keys {
    pub zpk: String,
    pub pvk: String,
    pub cvk: String,
    pub imk_ac: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StandIn {
    pub per_txn_limit_minor: i64,
    pub daily_limit_minor: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Circuit {
    pub failure_threshold: u32,
    pub open_ms: u64,
}

fn d_idle() -> u64 {
    300
}
fn d_inflight() -> usize {
    512
}
fn d_pool() -> usize {
    4
}
fn d_hsm_timeout() -> u64 {
    500
}
fn d_refresh() -> u64 {
    5
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Config> {
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }
}
