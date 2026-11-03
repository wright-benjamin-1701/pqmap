//! The curated crypto-capability matrix (plan 03) and the resolver that turns
//! a `(runtime, version, platform)` triple into a `TlsStack`.
//!
//! Every row carries `source_url` + `as_of` (provenance) so a stale claim is
//! provably stale. A row whose `as_of` is stale or whose `source_url` is
//! unreachable resolves to `pq-unknown` (never a stale `true`) — the
//! anti-liability rule (plan 03, 09 risk register).

mod matrix;
mod resolver;

pub use matrix::{chrono_lite, date_after, Matrix};
pub use resolver::Resolver;
