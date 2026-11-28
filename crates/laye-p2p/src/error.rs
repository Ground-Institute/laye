//! 「[Fable 5.2] laye-p2p's Errors: its origin, and the buffer the overlay drains.」
//!
//! "each adding things only they can now"
//! 「[Fable 5.2] An Error is made by `HERE`, laye-p2p's origin in sacred-error, which」
//! 「[Fable 5.2] fills in the id, the time, the source and the calling line. This module」
//! 「[Fable 5.2] keeps the buffer, and gives the origin its clock: JS Date on wasm32,」
//! 「[Fable 5.2] the system's on native.」

use sacred_error::{Anchor, Error, Origin, Severity, What};
use std::cell::RefCell;
use std::collections::VecDeque;

const CAP: usize = 100;

static HERE: Origin = Origin::new("laye-p2p", now_ms);

thread_local! {
    static BUFFER: RefCell<VecDeque<Error>> = const { RefCell::new(VecDeque::new()) };
}

#[cfg(target_arch = "wasm32")]
pub fn now_ms() -> String {
    (js_sys::Date::now() as u64).to_string()
}

/// 「[Fable 5.2] A clock set before 1970 gives no time, and none is invented.」
#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_default()
}

pub fn emit(error: Error) {
    BUFFER.with(|b| {
        let mut b = b.borrow_mut();
        if b.len() >= CAP {
            b.pop_front();
        }
        b.push_back(error);
    });
}

pub fn drain() -> Vec<Error> {
    BUFFER.with(|b| b.borrow_mut().drain(..).collect())
}

pub fn peek_all() -> Vec<Error> {
    BUFFER.with(|b| b.borrow().iter().cloned().collect())
}

pub fn clear() {
    BUFFER.with(|b| b.borrow_mut().clear());
}

/// 「[Fable 5.2] What broke at a laye boundary, made where it broke.」
#[track_caller]
pub fn build(
    severity: Severity,
    surface: &str,
    region: &str,
    title: &str,
    why: impl Into<String>,
) -> Error {
    let mut what = What::new(severity, surface, title, why);
    what.context.region = Some(region.to_string());
    HERE.make(what)
}

/// 「[Fable 5.2] The panic hook makes this: the panic's own location, not the hook's.」
pub fn build_panic(location: Option<String>, message: String, raw_stderr: Option<String>) -> Error {
    let mut what = What::new(Severity::Panic, "laye-p2p", "laye-p2p panicked", message);
    what.context.region = Some("wasm-panic".to_string());
    what.location = location;
    what.raw_stderr = raw_stderr;
    what.requires_reload = true;
    HERE.make(what)
}

/// Attach cursor anchor for click-triggered errors.
pub fn with_anchor(e: Error, x: f64, y: f64) -> Error {
    e.anchored(Anchor { x, y })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn what_is_made_has_its_own_id_and_says_who_made_it() {
        let a = build(Severity::Warn, "test", "region", "title", "why");
        let b = build(Severity::Warn, "test", "region", "title", "why");
        assert_ne!(a.id(), b.id());
        assert_eq!(a.source(), Some("laye-p2p"));
    }

    #[test]
    fn emit_and_drain_returns_pushed_error() {
        clear();
        let e = build(Severity::Warn, "test", "region", "title", "why");
        let id = e.id().to_string();
        emit(e);
        let drained = drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].id(), id);
        assert_eq!(drained[0].severity(), Severity::Warn);
        assert_eq!(drained[0].context().surface, "test");
        assert_eq!(drained[0].context().region.as_deref(), Some("region"));
        assert!(drain().is_empty());
    }

    #[test]
    fn buffer_evicts_oldest_when_over_cap() {
        clear();
        for i in 0..CAP + 5 {
            emit(build(
                Severity::Info,
                "test",
                "region",
                &format!("t{i}"),
                format!("w{i}"),
            ));
        }
        let all = peek_all();
        assert_eq!(all.len(), CAP);
        assert_eq!(all[0].title(), "t5");
        assert_eq!(all.last().unwrap().title(), format!("t{}", CAP + 4));
    }

    #[test]
    fn with_anchor_populates_context() {
        clear();
        let e = build(Severity::Error, "s", "r", "t", "w");
        let e = with_anchor(e, 100.0, 200.0);
        let a = e.context().anchor.unwrap();
        assert_eq!(a.x, 100.0);
        assert_eq!(a.y, 200.0);
    }
}
