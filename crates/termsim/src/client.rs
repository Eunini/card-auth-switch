//! Acquirer-side TCP client: 2-byte length framing, pipelined requests
//! matched to responses by terminal id + STAN.

use futures::{SinkExt, StreamExt};
use iso8583::{Message, Spec};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

type Pending = Arc<Mutex<HashMap<(String, String), oneshot::Sender<Message>>>>;

pub struct AcquirerClient {
    tx: mpsc::Sender<bytes::Bytes>,
    pending: Pending,
    spec: Spec,
    pub timeout: Duration,
}

fn key(m: &Message) -> (String, String) {
    (
        m.get_str(41).unwrap_or("").trim().to_string(),
        m.get_str(11).unwrap_or("").to_string(),
    )
}

impl AcquirerClient {
    pub async fn connect(addr: &str) -> anyhow::Result<Self> {
        let sock = TcpStream::connect(addr).await?;
        sock.set_nodelay(true)?;
        let codec = LengthDelimitedCodec::builder()
            .length_field_length(2)
            .max_frame_length(u16::MAX as usize)
            .new_codec();
        let (mut sink, mut stream) = Framed::new(sock, codec).split();
        let (tx, mut rx) = mpsc::channel::<bytes::Bytes>(4096);
        tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                if sink.send(b).await.is_err() {
                    break;
                }
            }
        });
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let p = pending.clone();
        let spec = Spec::v1987_ascii();
        let rspec = spec.clone();
        tokio::spawn(async move {
            while let Some(Ok(frame)) = stream.next().await {
                match Message::decode(&rspec, &frame) {
                    Ok(m) => {
                        if let Some(s) = p.lock().expect("lock").remove(&key(&m)) {
                            let _ = s.send(m);
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "undecodable response"),
                }
            }
        });
        Ok(Self {
            tx,
            pending,
            spec,
            timeout: Duration::from_secs(5),
        })
    }

    pub async fn send(&self, m: &Message) -> anyhow::Result<(Message, Duration)> {
        let bytes = m.encode(&self.spec)?;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("lock").insert(key(m), tx);
        let t0 = Instant::now();
        self.tx.send(bytes.into()).await?;
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(r)) => Ok((r, t0.elapsed())),
            Ok(Err(_)) => anyhow::bail!("connection closed"),
            Err(_) => {
                self.pending.lock().expect("lock").remove(&key(m));
                anyhow::bail!("timeout waiting for response")
            }
        }
    }
}
