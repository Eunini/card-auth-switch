//! Async multiplexed HSM client.
//!
//! A small pool of TCP connections; each connection carries many in-flight
//! requests correlated by id. A dead connection is re-established lazily
//! on the next call that lands on it.

use crate::proto::{Command, HsmError, Reply, Request, Response};
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HSM unavailable: {0}")]
    Unavailable(String),
    #[error("HSM timeout")]
    Timeout,
    #[error("HSM error: {0}")]
    Hsm(#[from] HsmError),
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Reply, HsmError>>>>>;

struct Conn {
    tx: mpsc::Sender<(u64, Vec<u8>)>,
    pending: Pending,
    alive: Arc<AtomicBool>,
}

pub struct HsmClient {
    addr: String,
    conns: Vec<tokio::sync::Mutex<Option<Conn>>>,
    next_id: AtomicU64,
    rr: AtomicUsize,
    timeout: Duration,
}

fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(u16::MAX as usize)
        .new_codec()
}

async fn open(addr: &str) -> Result<Conn, ClientError> {
    let sock = TcpStream::connect(addr)
        .await
        .map_err(|e| ClientError::Unavailable(e.to_string()))?;
    let _ = sock.set_nodelay(true);
    let (mut sink, mut stream) = Framed::new(sock, codec()).split();
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let alive = Arc::new(AtomicBool::new(true));
    let (tx, mut rx) = mpsc::channel::<(u64, Vec<u8>)>(4096);

    let p = pending.clone();
    let a = alive.clone();
    tokio::spawn(async move {
        while let Some((id, bytes)) = rx.recv().await {
            if sink.send(bytes.into()).await.is_err() {
                a.store(false, Ordering::SeqCst);
                if let Some(s) = p.lock().expect("pending lock").remove(&id) {
                    let _ = s.send(Err(HsmError::Malformed("connection lost".into())));
                }
                break;
            }
        }
    });

    let p = pending.clone();
    let a = alive.clone();
    tokio::spawn(async move {
        while let Some(Ok(frame)) = stream.next().await {
            if let Ok(resp) = serde_json::from_slice::<Response>(&frame) {
                if let Some(s) = p.lock().expect("pending lock").remove(&resp.id) {
                    let _ = s.send(resp.result);
                }
            }
        }
        a.store(false, Ordering::SeqCst);
        // Fail everything still waiting on this connection.
        for (_, s) in p.lock().expect("pending lock").drain() {
            let _ = s.send(Err(HsmError::Malformed("connection lost".into())));
        }
    });

    Ok(Conn { tx, pending, alive })
}

impl HsmClient {
    pub async fn connect(addr: &str, pool: usize, timeout: Duration) -> Result<Self, ClientError> {
        let c = Self {
            addr: addr.to_string(),
            conns: (0..pool.max(1))
                .map(|_| tokio::sync::Mutex::new(None))
                .collect(),
            next_id: AtomicU64::new(1),
            rr: AtomicUsize::new(0),
            timeout,
        };
        // Fail fast if the HSM is not there at startup.
        c.call(Command::Echo {
            data: "ping".into(),
        })
        .await?;
        Ok(c)
    }

    pub async fn call(&self, cmd: Command) -> Result<Reply, ClientError> {
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let bytes = serde_json::to_vec(&Request { id, cmd })
            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        {
            let mut slot = self.conns[idx].lock().await;
            let needs_open = match slot.as_ref() {
                Some(c) => !c.alive.load(Ordering::SeqCst),
                None => true,
            };
            if needs_open {
                *slot = Some(open(&self.addr).await?);
            }
            let conn = slot.as_ref().expect("connection present");
            conn.pending.lock().expect("pending lock").insert(id, tx);
            if conn.tx.send((id, bytes)).await.is_err() {
                conn.pending.lock().expect("pending lock").remove(&id);
                conn.alive.store(false, Ordering::SeqCst);
                return Err(ClientError::Unavailable("writer closed".into()));
            }
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(r)) => Ok(r?),
            Ok(Err(_)) => Err(ClientError::Unavailable("connection dropped".into())),
            Err(_) => {
                if let Some(c) = self.conns[idx].lock().await.as_ref() {
                    c.pending.lock().expect("pending lock").remove(&id);
                }
                Err(ClientError::Timeout)
            }
        }
    }
}
