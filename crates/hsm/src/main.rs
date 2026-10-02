use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use hsm::keyblock::Lmk;
use hsm::proto::KeyType;
use hsm::server::{serve, Hsm};
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "Simulated payment HSM (NOT a real HSM; for demonstration only)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HSM command server.
    Serve {
        #[arg(long, default_value = "127.0.0.1:27910")]
        listen: String,
        /// File with the 32-byte LMK in hex.
        #[arg(long)]
        lmk_file: String,
        /// Allow key-ceremony commands (FormKeyFromComponents).
        #[arg(long)]
        authorized: bool,
    },
    /// Offline key ceremony helper: wrap a clear test key under the LMK.
    Wrap {
        #[arg(long)]
        lmk_file: String,
        /// ZMK, ZPK, PVK, CVK or IMK
        #[arg(long = "type")]
        key_type: String,
        /// 16-byte clear key, hex
        #[arg(long)]
        clear: String,
    },
}

fn load_lmk(path: &str) -> anyhow::Result<Lmk> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let hex: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    Lmk::from_hex(&hex).map_err(|e| anyhow!(e))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Serve {
            listen,
            lmk_file,
            authorized,
        } => {
            let lmk = load_lmk(&lmk_file)?;
            tracing::info!(lmk_kcv = lmk.kcv(), %listen, authorized, "simulated HSM starting");
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            serve(listener, Arc::new(Hsm::new(lmk, authorized))).await?;
        }
        Cmd::Wrap {
            lmk_file,
            key_type,
            clear,
        } => {
            let lmk = load_lmk(&lmk_file)?;
            let kt = KeyType::parse(&key_type).ok_or_else(|| anyhow!("unknown key type"))?;
            let k: [u8; 16] = hex::decode(&clear)?
                .try_into()
                .map_err(|_| anyhow!("key must be 16 bytes"))?;
            println!("key_block = \"{}\"", lmk.wrap(kt, &k));
            println!("kcv = \"{}\"", hex::encode_upper(cardcrypto::des3::kcv(&k)));
        }
    }
    Ok(())
}
