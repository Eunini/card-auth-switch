//! Store-and-forward (SAF) journal for advices.
//!
//! An append-only file of JSON lines:
//!
//! ```text
//! {"op":"enq","seq":17,"mti":"0120","item":{...}}
//! {"op":"ack","seq":17}
//! ```
//!
//! * `enqueue` returns only after the line is on disk (fdatasync), so a
//!   stand-in approval is never sent to the terminal before its advice is
//!   durable. Concurrent enqueues are group-committed: one fsync covers
//!   every line written in the same batch.
//! * `ack` is appended without fsync. Losing an ack in a crash only causes
//!   a re-delivery, which the issuer de-duplicates by advice/reversal id.
//! * On open, the file is replayed to rebuild the pending set; a torn last
//!   line (crash mid-write) is ignored.
//! * When nothing is pending and the file has grown, it is truncated.
//!
//! The journal never contains PANs: items reference cards by id.

use crate::issuer::{AdviceRequest, ReversalRequest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
#[allow(clippy::large_enum_variant)]
pub enum SafItem {
    AuthAdvice(AdviceRequest),
    Reversal(ReversalRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafEntry {
    pub seq: u64,
    /// ISO 8583 MTI the entry represents (0120 auth advice, 0420 reversal advice).
    pub mti: String,
    pub item: SafItem,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
#[allow(clippy::large_enum_variant)]
enum Line {
    Enq(SafEntry),
    Ack { seq: u64 },
}

struct Write {
    bytes: Vec<u8>,
    sync: bool,
    done: Option<oneshot::Sender<io::Result<()>>>,
}

pub struct Journal {
    tx: mpsc::Sender<Write>,
    pending: Arc<Mutex<BTreeMap<u64, SafEntry>>>,
    next_seq: AtomicU64,
}

const COMPACT_THRESHOLD: u64 = 256 * 1024;

impl Journal {
    pub async fn open(path: &str) -> io::Result<Arc<Journal>> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let mut pending = BTreeMap::new();
        let mut max_seq = 0;
        if let Ok(raw) = tokio::fs::read(path).await {
            // Drop a torn trailing line so new appends start on a clean line.
            let keep = raw.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            if keep < raw.len() {
                tracing::warn!(bytes = raw.len() - keep, "truncating torn SAF journal tail");
                let f = OpenOptions::new().write(true).open(path).await?;
                f.set_len(keep as u64).await?;
                f.sync_all().await?;
            }
            let text = String::from_utf8_lossy(&raw[..keep]);
            for (i, line) in text.lines().enumerate() {
                match serde_json::from_str::<Line>(line) {
                    Ok(Line::Enq(e)) => {
                        max_seq = max_seq.max(e.seq);
                        pending.insert(e.seq, e);
                    }
                    Ok(Line::Ack { seq }) => {
                        max_seq = max_seq.max(seq);
                        pending.remove(&seq);
                    }
                    Err(e) => {
                        tracing::warn!(line = i + 1, error = %e, "ignoring unreadable SAF journal line")
                    }
                }
            }
        }
        if !pending.is_empty() {
            tracing::info!(
                pending = pending.len(),
                "SAF journal recovered pending advices"
            );
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        let pending = Arc::new(Mutex::new(pending));
        let (tx, rx) = mpsc::channel(8192);
        tokio::spawn(writer(file, rx, pending.clone()));
        Ok(Arc::new(Journal {
            tx,
            pending,
            next_seq: AtomicU64::new(max_seq + 1),
        }))
    }

    /// Durably append an advice. Returns its sequence number once fsynced.
    pub async fn enqueue(&self, mti: &str, item: SafItem) -> io::Result<u64> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let entry = SafEntry {
            seq,
            mti: mti.to_string(),
            item,
        };
        let mut bytes = serde_json::to_vec(&Line::Enq(entry.clone()))?;
        bytes.push(b'\n');
        self.pending
            .lock()
            .expect("journal lock")
            .insert(seq, entry);
        let (done, rx) = oneshot::channel();
        self.tx
            .send(Write {
                bytes,
                sync: true,
                done: Some(done),
            })
            .await
            .map_err(|_| io::Error::other("journal writer stopped"))?;
        match rx.await {
            Ok(Ok(())) => Ok(seq),
            Ok(Err(e)) => {
                self.pending.lock().expect("journal lock").remove(&seq);
                Err(e)
            }
            Err(_) => Err(io::Error::other("journal writer stopped")),
        }
    }

    pub async fn ack(&self, seq: u64) {
        self.pending.lock().expect("journal lock").remove(&seq);
        let mut bytes = serde_json::to_vec(&Line::Ack { seq }).expect("serialize ack");
        bytes.push(b'\n');
        let _ = self
            .tx
            .send(Write {
                bytes,
                sync: false,
                done: None,
            })
            .await;
    }

    /// Pending entries in FIFO order.
    pub fn pending(&self) -> Vec<SafEntry> {
        self.pending
            .lock()
            .expect("journal lock")
            .values()
            .cloned()
            .collect()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.lock().expect("journal lock").len()
    }
}

async fn writer(
    mut file: File,
    mut rx: mpsc::Receiver<Write>,
    pending: Arc<Mutex<BTreeMap<u64, SafEntry>>>,
) {
    let mut written: u64 = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        while batch.len() < 512 {
            match rx.try_recv() {
                Ok(w) => batch.push(w),
                Err(_) => break,
            }
        }
        let mut buf = Vec::new();
        let mut need_sync = false;
        for w in &batch {
            buf.extend_from_slice(&w.bytes);
            need_sync |= w.sync;
        }
        let mut res = file.write_all(&buf).await;
        if res.is_ok() && need_sync {
            res = file.sync_data().await;
        }
        written += buf.len() as u64;
        for w in batch {
            if let Some(d) = w.done {
                let _ = d.send(match &res {
                    Ok(()) => Ok(()),
                    Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
                });
            }
        }
        let idle = written > COMPACT_THRESHOLD && pending.lock().expect("journal lock").is_empty();
        if idle && file.set_len(0).await.is_ok() && file.sync_data().await.is_ok() {
            written = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::ReversalRequest;

    fn rev(n: u64) -> SafItem {
        SafItem::Reversal(ReversalRequest {
            reversal_ref: format!("r{n}"),
            auth_ref: format!("a{n}"),
            replacement_amount_minor: None,
            reason: "test".into(),
        })
    }

    #[tokio::test]
    async fn survives_restart_and_tolerates_torn_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saf.log").to_string_lossy().to_string();
        {
            let j = Journal::open(&path).await.unwrap();
            let a = j.enqueue("0420", rev(1)).await.unwrap();
            let _b = j.enqueue("0420", rev(2)).await.unwrap();
            let _c = j.enqueue("0420", rev(3)).await.unwrap();
            j.ack(a).await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // Simulate a crash in the middle of writing a line.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, b"{\"op\":\"enq\",\"seq\":9,\"mti").unwrap();
        drop(f);

        let j = Journal::open(&path).await.unwrap();
        let p = j.pending();
        assert_eq!(p.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(p[0].item, rev(2));
        // New sequence numbers continue after the highest seen, and the
        // torn tail does not corrupt the next record.
        let s = j.enqueue("0420", rev(4)).await.unwrap();
        assert!(s > 3);
        drop(j);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let j = Journal::open(&path).await.unwrap();
        assert_eq!(
            j.pending().iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![2, 3, s]
        );
    }

    #[tokio::test]
    async fn concurrent_enqueues_group_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saf.log").to_string_lossy().to_string();
        let j = Journal::open(&path).await.unwrap();
        let mut hs = Vec::new();
        for i in 0..200 {
            let j = j.clone();
            hs.push(tokio::spawn(async move {
                j.enqueue("0120", rev(i)).await.unwrap()
            }));
        }
        for h in hs {
            h.await.unwrap();
        }
        assert_eq!(j.pending_len(), 200);
        let j2 = Journal::open(&path).await.unwrap();
        assert_eq!(j2.pending_len(), 200);
    }
}
