//! `pq-probe` — live TLS / handshake verification (plan 04).
//!
//! Design invariants (validated by the unit tests):
//!
//! 1. **Allowlist by default-deny** (plan 04 rule 1, plan 08 #5): hosts that
//!    are not in `ProbeOptions::allow` are never connected to; the denial
//!    returns `zero_packets: true` so CI can assert zero external traffic.
//!    Loopback is auto-allowed in non-strict mode (local development scan
//!    carve-out, plan 04 rule 1); strict mode blocks it.
//! 2. **Two offering round-trips** (plan 04 "offering policy"): a classical
//!    baseline (no PQ groups offered) and a PQ-preferring round. Only when a
//!    PQ round negotiates a ML-KEM hybrid is `server_negotiated_pq = true`.
//!    This is the only way to distinguish `pq-negotiated` from `pq-capable`.
//! 3. **No fuzzing / no downgrade attacks** (plan 04): we run *standard*
//!    handshakes only; one `complete_io` per round-trip; no `key_share` for
//!    PQ in the classical baseline (the provider's group order controls the
//!    offering set).
//! 4. **Passive client-cert observation only** (plan 04 rule 5): we record
//!    `server_requested_client_cert = false` by default; the V1 client does
//!    not satisfy any client-cert challenge.
//! 5. **In-binary client** (plan 04 rationale): no `openssl s_client` shell
//!    out, so we cannot inherit a corporate MITM proxy's `OPENSSL_CONF`.
//! 6. **Trust the roots you give us** — V1 accepts a caller-supplied CA
//!    bundle (for tests, the server's self-signed cert). This matches plan 04
//!    rule 5 "we do not trust the client OS store."

use std::sync::Arc;

pub mod allowlist;
pub mod client;
pub mod server;

pub use allowlist::{AllowedHost, HostAllowlist};
pub use client::{probe_target, ProbeError, ProbeOptions};
pub use server::TestServer;

/// A probe target = one `host:port:scheme` triple.
#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub scheme: String,
}

impl Target {
    pub fn localhost() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 443,
            scheme: "https".into(),
        }
    }
    pub fn new(host: impl Into<String>, port: u16, scheme: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            scheme: scheme.into(),
        }
    }
    pub fn is_loopback(&self) -> bool {
        self.host == "127.0.0.1" || self.host == "localhost" || self.host == "[::1]"
    }
}

/// Outcome of one `probe_target` call.
pub struct ProbeOutcome {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub facts: Option<pq_core::HandshakeFacts>,
    pub error: Option<ProbeError>,
    /// Plan 08 acceptance #5: `true` ⇒ zero external packets were sent.
    pub zero_packets: bool,
}

/// One round-trip's observed facts (baseline or PQ offering).
#[derive(Clone, Debug)]
pub struct RoundResult {
    pub group: String,
    pub is_pq: bool,
    pub suite: String,
    pub tls_version: String,
    pub cert_spki_sha256: String,
    pub cert_sig_alg: String,
    pub cert_issuer: String,
    pub cert_subject: String,
    pub cert_validity_start: String,
    pub cert_validity_end: String,
    pub alpn: Vec<String>,
    pub rtt_ms: u32,
}

/// rustls provider whose offering set excludes all PQ groups (baseline).
pub fn classical_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    let prov = rustls::crypto::aws_lc_rs::default_provider();
    let mut prov = prov;
    prov.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    Some(Arc::new(prov))
}

/// rustls provider with PQ hybrid first (the PQ offering round-trip).
pub fn pq_provider() -> Option<Arc<rustls::crypto::CryptoProvider>> {
    let prov = rustls::crypto::aws_lc_rs::default_provider();
    let mut prov = prov;
    prov.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    Some(Arc::new(prov))
}
