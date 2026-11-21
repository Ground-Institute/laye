//! Connections a host hands in, for a peer that takes them in wasm32.

// "relaye is dead. Make laye-net able to accept connections"

// "I want a new node, on cloudflare, called C"

// 「[Opus 5.5] A browser cannot listen. A host that takes WebSockets for laye, a
// Cloudflare Durable Object, hands each one in through an Accepting, and the
// swarm takes it as an incoming connection.」

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::task::{Context, Poll};

use futures::channel::mpsc;
use futures::future::{Ready, ready};
use futures::task::AtomicWaker;
use futures::{AsyncRead, AsyncWrite, Stream};
use libp2p::Multiaddr;
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use send_wrapper::SendWrapper;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{MessageEvent, WebSocket};

/// Where a host hands in the WebSockets it took. Each is one connection.
#[derive(Clone)]
pub struct Accepting(mpsc::UnboundedSender<Accepted>);

impl Accepting {
    /// Hand in a WebSocket before the host accepts it. False when the peer is
    /// gone.
    ///
    /// A message that arrives with no listener on the socket is dropped, and
    /// the first bytes a dialer sends come at once, so the socket is listened
    /// to here, before it is accepted, and not when the swarm reaches it.
    pub fn accept(&self, socket: WebSocket) -> bool {
        self.0.unbounded_send(Accepted::new(socket)).is_ok()
    }
}

pub(crate) fn accepting() -> (Accepting, Taken) {
    let (tx, rx) = mpsc::unbounded();
    (
        Accepting(tx),
        Taken {
            incoming: rx,
            listener: None,
            announced: true,
        },
    )
}

/// The transport side: WebSockets handed in become incoming connections on the
/// one address the peer was told it listens on. It dials nothing.
pub(crate) struct Taken {
    incoming: mpsc::UnboundedReceiver<Accepted>,
    listener: Option<(ListenerId, Multiaddr)>,
    announced: bool,
}

impl Transport for Taken {
    type Output = Accepted;
    type Error = io::Error;
    type ListenerUpgrade = Ready<Result<Accepted, io::Error>>;
    type Dial = Ready<Result<Accepted, io::Error>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<io::Error>> {
        if self.listener.is_some() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        self.listener = Some((id, addr));
        self.announced = false;
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        if self.listener.as_ref().is_some_and(|(held, _)| *held == id) {
            self.listener = None;
            return true;
        }
        false
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<io::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, io::Error>> {
        let Some((id, addr)) = self.listener.clone() else {
            return Poll::Pending;
        };
        if !self.announced {
            self.announced = true;
            return Poll::Ready(TransportEvent::NewAddress {
                listener_id: id,
                listen_addr: addr,
            });
        }
        match Pin::new(&mut self.incoming).poll_next(cx) {
            Poll::Ready(Some(accepted)) => Poll::Ready(TransportEvent::Incoming {
                listener_id: id,
                upgrade: ready(Ok(accepted)),
                local_addr: addr.clone(),
                send_back_addr: addr,
            }),
            Poll::Ready(None) => {
                self.listener = None;
                Poll::Ready(TransportEvent::ListenerClosed {
                    listener_id: id,
                    reason: Ok(()),
                })
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// One WebSocket the host handed in, read and written as bytes.
pub struct Accepted {
    inner: SendWrapper<Inner>,
}

struct Inner {
    socket: WebSocket,
    read: Rc<Mutex<VecDeque<u8>>>,
    waker: Rc<AtomicWaker>,
    closed: Rc<Mutex<bool>>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(web_sys::Event)>,
}

impl Accepted {
    fn new(socket: WebSocket) -> Self {
        // A binary frame arrives as whatever binaryType says; only an
        // ArrayBuffer reads as bytes. Nothing else read as bytes reads as 0.
        socket.set_binary_type(web_sys::BinaryType::Arraybuffer);
        let read = Rc::new(Mutex::new(VecDeque::new()));
        let waker = Rc::new(AtomicWaker::new());
        let closed = Rc::new(Mutex::new(false));
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new({
            let read = read.clone();
            let waker = waker.clone();
            move |e: MessageEvent| {
                let data = js_sys::Uint8Array::new(&e.data());
                read.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .extend(data.to_vec());
                waker.wake();
            }
        });
        let on_close = Closure::<dyn FnMut(web_sys::Event)>::new({
            let closed = closed.clone();
            let waker = waker.clone();
            move |_| {
                *closed.lock().unwrap_or_else(|p| p.into_inner()) = true;
                waker.wake();
            }
        });
        // A socket that takes no listener is one no byte comes through, so
        // the connection is closed from the start.
        let listened = socket
            .add_event_listener_with_callback("message", on_message.as_ref().unchecked_ref())
            .and_then(|()| {
                socket.add_event_listener_with_callback("close", on_close.as_ref().unchecked_ref())
            })
            .and_then(|()| {
                socket.add_event_listener_with_callback("error", on_close.as_ref().unchecked_ref())
            });
        if listened.is_err() {
            *closed.lock().unwrap_or_else(|p| p.into_inner()) = true;
        }
        Self {
            inner: SendWrapper::new(Inner {
                socket,
                read,
                waker,
                closed,
                _on_message: on_message,
                _on_close: on_close,
            }),
        }
    }
}

impl AsyncRead for Accepted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let inner = &*self.inner;
        inner.waker.register(cx.waker());
        let mut read = inner.read.lock().unwrap_or_else(|p| p.into_inner());
        if read.is_empty() {
            if *inner.closed.lock().unwrap_or_else(|p| p.into_inner()) {
                return Poll::Ready(Ok(0));
            }
            return Poll::Pending;
        }
        let n = buf.len().min(read.len());
        for (to, from) in buf.iter_mut().zip(read.drain(..n)) {
            *to = from;
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for Accepted {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = &*self.inner;
        if *inner.closed.lock().unwrap_or_else(|p| p.into_inner()) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // A copy of its own, not a view into wasm's memory: what is sent is
        // these bytes, whatever the memory holds after.
        let copy = js_sys::Uint8Array::from(buf);
        match inner.socket.send_with_array_buffer(&copy.buffer()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::other(format!("{e:?}")))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = &*self.inner;
        *inner.closed.lock().unwrap_or_else(|p| p.into_inner()) = true;
        Poll::Ready(
            inner
                .socket
                .close()
                .map_err(|e| io::Error::other(format!("{e:?}"))),
        )
    }
}

impl Drop for Inner {
    // A socket left open holds the browser's side with nothing reading it. Its
    // listeners go first: they are dropped with this, and the close it fires
    // would call them after.
    fn drop(&mut self) {
        let on_message = self._on_message.as_ref().unchecked_ref();
        let on_close = self._on_close.as_ref().unchecked_ref();
        drop(
            self.socket
                .remove_event_listener_with_callback("message", on_message),
        );
        drop(
            self.socket
                .remove_event_listener_with_callback("close", on_close),
        );
        drop(
            self.socket
                .remove_event_listener_with_callback("error", on_close),
        );
        drop(self.socket.close());
    }
}
