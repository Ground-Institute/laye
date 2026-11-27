#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// "laye is supposed to solve that longer term, making QNTX be able to be more experimental, while laye becomes the stable auth and identity layer"

// QNTX streams some answers: an agent's live output, an A2A stream. In front
// of QNTX, laye passes each part on as it comes, not once the stream ends.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use laye_front::Config;
use tokio::net::TcpListener;

/// A QNTX that sends its first part at once and keeps the stream open.
async fn streaming_qntx() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(|_req: Request<hyper::body::Incoming>| async {
                        let (tx, rx) =
                            tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
                        tokio::spawn(async move {
                            tx.send(Ok(Frame::data(Bytes::from_static(b"data: first\n\n"))))
                                .await
                                .unwrap();
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        });
                        let body = StreamBody::new(tokio_stream_of(rx));
                        Ok::<_, Infallible>(Response::new(body))
                    });
                let _served = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

fn tokio_stream_of<T: Send + 'static>(
    mut rx: tokio::sync::mpsc::Receiver<T>,
) -> impl futures::Stream<Item = T> + Send + 'static {
    futures::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_part_of_a_stream_arrives_while_qntx_still_streams() {
    let qntx = streaming_qntx().await;
    let dir = std::env::temp_dir().join(format!("laye-stream-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (front, _run) = laye_front::start(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            qntx: format!("http://{qntx}"),
            qntx_did: "did:key:z6MkqntxNodeStandsHere".into(),
            public_origins: vec!["https://api.q.example".into()],
            held_at: dir.join("held.jsonl"),
            root_identities: Vec::new(),
            binding_signers: Vec::new(),
            issuer: "https://laye.example".into(),
            nodes: Vec::new(),
            invitations_at: dir.join("invitations.jsonl"),
            ceremony_at: "https://node.example".into(),
            names: None,
            passkeys: None,
            web: None,
            apns: None,
            pack_nodes: Vec::new(),
            governed: None,
        },
        laye_me::fresh(),
    )
    .await
    .unwrap();

    let stream = tokio::net::TcpStream::connect(front.addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::get("/api/agent/live")
        .header("host", "api.q.example")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let mut body = resp.into_body();
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("laye held the stream back until it ends")
        .unwrap()
        .unwrap();
    assert_eq!(
        first.into_data().unwrap(),
        Bytes::from_static(b"data: first\n\n")
    );
}
