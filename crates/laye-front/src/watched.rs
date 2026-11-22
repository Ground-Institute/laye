//! What is collected for a person, pushed to them as it changes.

// "i see, so it's workable now, but isn't spectacular to demo or be a daily driver, this is very much an early prototype of the core idea."
//
// mycelia asked laye for what is collected every five minutes, so what an
// agent said reached ag up to five minutes late. Here laye holds the asking
// open: it watches etcd under its /collected/, and says the person's whole
// again each time a key there changes, as server-sent events.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Frame, SizeHint};
use tokio::sync::mpsc;

use crate::{Inner, collected};

/// How long one watch is held before the asker is sent away to ask again,
/// and its session checked again.
pub const LIFE: Duration = Duration::from_secs(3600);
/// How often a comment is said while nothing changes: what tells laye the
/// asker is gone, and keeps whatever stands between them from closing it.
const QUIET: Duration = Duration::from_secs(25);
/// How long laye waits before watching again after etcd did not answer.
const AGAIN: Duration = Duration::from_secs(5);

/// A body laye says into as it goes.
pub struct Pushed(mpsc::Receiver<Bytes>);

impl hyper::body::Body for Pushed {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|said| said.map(|b| Ok(Frame::data(b))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// One event: the person's whole, as `GET /laye/collected` answers it.
fn event(whole: &str) -> Bytes {
    Bytes::from(format!("data: {whole}\n\n"))
}

/// Whether what etcd said on a watch is a change, or the watch ending: its
/// first message, that the watch was made, is neither.
pub fn changed(said: &str) -> bool {
    ["\"events\"", "\"canceled\"", "\"error\""]
        .iter()
        .any(|word| said.contains(word))
}

/// The person's whole, then again on each change, until they go or `LIFE`.
pub(crate) fn watch(inner: Arc<Inner>, person: String, level: String) -> Pushed {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let Some(keys) = inner.passkeys.as_ref() else {
            return;
        };
        let held = collected::Collections {
            etcd: &keys.etcd,
            laye: &inner.did,
        };
        let prefix = format!("{}{}/", collected::COLLECTED, inner.did);
        let until = tokio::time::Instant::now() + LIFE;
        let mut last = String::new();
        let mut fresh = false;
        loop {
            // Watched before it is read, so nothing written between is missed.
            let watching = keys.etcd.watch(&prefix, fresh).await;
            let (_, whole) = crate::collected_for(&held, &person, &level).await;
            let whole = whole.to_string();
            if whole != last {
                if tx.send(event(&whole)).await.is_err() {
                    return;
                }
                last = whole;
            }
            let mut body = match watching {
                Ok(body) => body,
                Err(why) => {
                    eprintln!("laye-front: what is collected is not watched: {why}");
                    fresh = true;
                    tokio::select! {
                        () = tokio::time::sleep(AGAIN) => continue,
                        () = tokio::time::sleep_until(until) => return,
                        () = tx.closed() => return,
                    }
                }
            };
            fresh = false;
            let mut said = String::new();
            loop {
                tokio::select! {
                    frame = body.frame() => match frame {
                        Some(Ok(frame)) => {
                            if let Some(data) = frame.data_ref() {
                                said.push_str(&String::from_utf8_lossy(data));
                            }
                            if changed(&said) {
                                // A watch refused for its token says "error".
                                fresh = said.contains("\"error\"");
                                break;
                            }
                        }
                        // etcd ended the watch: watched again, and read again.
                        _ => break,
                    },
                    () = tokio::time::sleep(QUIET) => {
                        if tx.send(Bytes::from_static(b": quiet\n\n")).await.is_err() {
                            return;
                        }
                    }
                    () = tokio::time::sleep_until(until) => return,
                    () = tx.closed() => return,
                }
            }
        }
    });
    Pushed(rx)
}
