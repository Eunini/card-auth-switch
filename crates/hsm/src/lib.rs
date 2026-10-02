//! Simulated payment HSM.
//!
//! **This is not a real HSM.** It runs as an ordinary process, keeps its
//! local master key (LMK) in memory loaded from a file, and has no tamper
//! protection, no secure key storage and no certification (FIPS 140 / PCI
//! PTS HSM). It exists to show the *shape* of an HSM integration: keys
//! live only as LMK-wrapped blocks outside the HSM, and the host can only
//! ask narrow questions ("is this PIN right?", "is this ARQC valid?").
//!
//! * [`proto`] - command/reply types (always available)
//! * [`client`] - async multiplexed client (always available)
//! * `keyblock`, `server` - the HSM itself (feature `server`)

pub mod client;
pub mod proto;

#[cfg(feature = "server")]
pub mod keyblock;
#[cfg(feature = "server")]
pub mod server;
