//! TCP front end: 2-byte length-prefixed ISO 8583 frames.
//!
//! Each connection has a reader loop and a writer task. Requests are
//! processed concurrently (bounded per connection); the acquirer matches
//! responses by STAN/RRN, so responses may be written out of order. A
//! connection idle for longer than `idle_timeout` is closed.

use crate::engine::{Session, Switch};
use crate::rc;
use futures::{SinkExt, StreamExt};
use iso8583::{Message, Mti};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(2)
        .max_frame_length(u16::MAX as usize)
        .new_codec()
}

pub async fn serve(listener: TcpListener, sw: Arc<Switch>) -> std::io::Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let sw = sw.clone();
        tokio::spawn(async move {
            tracing::info!(%peer, "acquirer connected");
            handle_conn(sock, sw).await;
            tracing::info!(%peer, "acquirer disconnected");
        });
    }
}

async fn handle_conn(sock: TcpStream, sw: Arc<Switch>) {
    let (mut sink, mut stream) = Framed::new(sock, codec()).split();
    let (tx, mut rx) = mpsc::channel::<bytes::Bytes>(1024);
    let writer = tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            if sink.send(b).await.is_err() {
                break;
            }
        }
    });
    let session = Arc::new(Session::default());
    let limit = Arc::new(Semaphore::new(sw.cfg.max_in_flight_per_conn.max(1)));
    let idle = Duration::from_secs(sw.cfg.idle_timeout_secs.max(1));

    loop {
        let frame = match tokio::time::timeout(idle, stream.next()).await {
            Err(_) => {
                tracing::info!("closing idle connection");
                break;
            }
            Ok(None) => break,
            Ok(Some(Err(e))) => {
                tracing::warn!(error = %e, "framing error; closing connection");
                break;
            }
            Ok(Some(Ok(f))) => f,
        };
        let Ok(permit) = limit.clone().acquire_owned().await else {
            break;
        };
        let (sw, tx, session) = (sw.clone(), tx.clone(), session.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let resp = match Message::decode(&sw.spec, &frame) {
                Ok(msg) => sw.handle(msg, &session).await,
                Err(e) => format_error(&frame, &e),
            };
            if let Some(r) = resp {
                match r.encode(&sw.spec) {
                    Ok(b) => {
                        let _ = tx.send(b.into()).await;
                    }
                    Err(e) => tracing::error!(error = %e, "cannot encode response"),
                }
            }
        });
    }
    drop(tx);
    let _ = writer.await;
}

/// Best effort: if at least the MTI is readable, answer with RC 30 so the
/// acquirer is not left waiting for a timeout.
fn format_error(frame: &[u8], e: &iso8583::Error) -> Option<Message> {
    tracing::warn!(error = %e, "undecodable message");
    let mti = Mti::from_bytes(frame.get(0..4)?).ok()?;
    let mut r = Message::new(mti.response()?);
    r.set(39, rc::FORMAT_ERROR);
    Some(r)
}
