//! Runtime/crypto capability types (plan 03).
//!
//! These upgrade a static finding into a **runtime crypto claim** with
//! provenance. The KB matrix (kb crate) deserializes into `KbRow`; the resolver
//! produces a `TlsStack` for an edge.

use serde::{Deserialize, Serialize};

use crate::edge::Evidence;
use crate::{PqAxisState, Provenance};

/// Runtime / platform facts we capture for an edge (plan 02/03).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeFacts {
    /// Target framework moniker, e.g. `net10.0`, `node 22`, `python 3.12`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfm: Option<String>,
    /// Inferred OS: `linux` / `windows` / `macos` / `unknown` (plan 03).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Runtime name: `node` / `dotnet` / `python` / …
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Runtime version (best effort).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// For the Node case: the bundled OpenSSL version (drives PQ capability).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_openssl: Option<String>,
    /// Where these facts came from (IaC, Dockerfile, CI, runtimeconfig).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl RuntimeFacts {
    pub fn os(&self) -> Option<&str> {
        self.os.as_deref().filter(|o| *o != "unknown")
    }
}

/// A concrete TLS implementation (plan 03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsImplementation {
    #[serde(rename = "openssl")]
    OpenSSL,
    #[serde(rename = "schannel")]
    Schannel,
    #[serde(rename = "securetransport")]
    SecureTransport,
    #[serde(rename = "boringssl")]
    BoringSSL,
    #[serde(rename = "bouncycastle")]
    BouncyCastle,
    #[serde(rename = "webpki")]
    WebPki,
    #[serde(rename = "unknown")]
    Unknown,
}

impl std::fmt::Display for TlsImplementation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TlsImplementation::OpenSSL => "openssl",
            TlsImplementation::Schannel => "schannel",
            TlsImplementation::SecureTransport => "securetransport",
            TlsImplementation::BoringSSL => "boringssl",
            TlsImplementation::BouncyCastle => "bouncycastle",
            TlsImplementation::WebPki => "webpki",
            TlsImplementation::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// A single axis's capability, resolved from a KB row (plan 03 verdicts).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsCapability {
    pub state: PqAxisState,
    /// E.g. `["X25519MLKEM768"]` for KEM, `["ML-DSA-65"]` for signatures.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    pub source_url: String,
    pub as_of: String,
}

/// The resolved TLS stack for an edge (plan 03 `TlsStack` emitter).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsStack {
    pub impl_kind: TlsImplementation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub pq_kem: TlsCapability,
    pub pq_sig: TlsCapability,
    /// Provenance of the KB row used (plan 03 anti-liability).
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl TlsStack {
    /// A stack with no information (prefer over guessing).
    pub fn unknown() -> Self {
        Self {
            impl_kind: TlsImplementation::Unknown,
            version: None,
            os: None,
            pq_kem: TlsCapability {
                state: PqAxisState::PqUnknown,
                groups: vec![],
                source_url: "none".to_string(),
                as_of: String::new(),
            },
            pq_sig: TlsCapability {
                state: PqAxisState::PqUnknown,
                groups: vec![],
                source_url: "none".to_string(),
                as_of: String::new(),
            },
            provenance: Provenance {
                source_url: "none".to_string(),
                as_of: String::new(),
            },
            evidence: vec![],
        }
    }
}

/// A KB matrix row — one `(runtime, version, platform, tls_impl)` capability
/// record. This is the curated, machine-readable matrix (plan 03) the `kb`
/// crate deserializes from `crypto_matrix.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KbRow {
    pub row_id: String,
    /// e.g. `openssl`, `node`, `dotnet`, `python`, `schannel`.
    pub runtime: String,
    /// Minimum version, as a plain string (e.g. `3.5`, `22`, `10`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_min: Option<String>,
    /// e.g. `linux`, `windows`, `macos`, `any`.
    pub platform: String,
    pub tls_impl: TlsImplementation,
    /// System crypto provider, e.g. `openssl`, `boringssl`, `crypto-api`.
    pub provider: String,
    /// KEM/PQ truth for this row. A bool in the TOML; `false` = classical only.
    pub pq_kem: bool,
    /// `true` means we do NOT assert either way (plan 03: prefer `unknown`
    /// over a wrong `true`) — overrides `pq_kem`.
    #[serde(default)]
    pub pq_kem_unknown: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pq_kem_groups: Vec<String>,
    pub pq_sig: bool,
    #[serde(default)]
    pub pq_sig_unknown: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pq_sig_algs: Vec<String>,
    #[serde(default = "default_min_tls")]
    pub min_tls: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub quic: bool,
    /// Provenance: the URL is the source of truth, the plan is not (README).
    pub source_url: String,
    /// ISO date the row was last verified (drift-check compares `as_of`).
    pub as_of: String,
    /// If `true`, a human has verified this row beyond the `as_of` re-check —
    /// it will not be downgraded to `pq-unknown` when `as_of` is stale.
    #[serde(default)]
    pub verified: bool,
}

fn default_min_tls() -> String {
    "1.2".to_string()
}

/// An infrastructure KB row (plan 05): who terminates + is it PQ.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InfraKbRow {
    pub row_id: String,
    pub vendor: String,
    pub kind: String,
    /// `true` / `false` / not present => treat as `unknown` (prefer unknown).
    #[serde(default)]
    pub pq_kem: bool,
    #[serde(default)]
    pub pq_sig: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub source_url: String,
    pub as_of: String,
    #[serde(default)]
    pub verified: bool,
}

/// A dependency declaration discovered in a manifest/lockfile (plan 02/03).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub ecosystem: String,
    /// Which manifest/lockfile it came from.
    pub file: String,
}
