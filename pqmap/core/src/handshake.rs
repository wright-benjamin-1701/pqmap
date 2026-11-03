//! Live handshake facts (plan 04).
//!
//! A `HandshakeFacts` record is *observation evidence*: it is the only way to
//! distinguish `pq-negotiated` from `pq-capable`. Plan 04 is strict that we
//! don't fuzz / downgrade-attack; only standard handshake + one application
//! request. The records here capture that, with redactions applied.

use serde::{Deserialize, Serialize};

use crate::Evidence;

/// Facts recorded from a live handshake (plan 04 output).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeFacts {
    /// ISO-8601 UTC timestamp of the probe.
    pub at: String,
    /// TLS versions the server supported (ordered best-first).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_versions: Vec<String>,
    /// What was actually negotiated (per group-family round-trip, plan 04).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub negotiated: Vec<NegotiatedResult>,
    /// Offered in each round-trip (baseline + PQ-only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offered_groups: Vec<String>,
    /// `true` if any of the round-trips landed in a PQ hybrid group.
    #[serde(default)]
    pub server_negotiated_pq: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertFacts>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub quic: bool,
    /// JA3/JA4 client + server fingerprints (drift signal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4_server: Option<String>,
    /// RTT of the fastest handshake, ms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    /// If the server requested a client cert (passive observation only).
    #[serde(default)]
    pub server_requested_client_cert: bool,
    /// The probe report id (for auditing / cross-referencing).
    pub report_id: String,
    /// Provenance evidence: which KB row + allowlist policy authorizes this.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl HandshakeFacts {
    /// Best (highest-strength) PQ capability observed on *any* round-trip.
    pub fn best_group(&self) -> Option<&str> {
        self.negotiated
            .iter()
            .find(|r| r.group.contains("MLKEM") || r.group.contains("ML-KEM"))
            .map(|r| r.group.as_str())
            .or_else(|| {
                self.negotiated
                    .first()
                    .map(|r| r.group.as_str())
            })
    }
}

/// A single round-trip's negotiated result (plan 04: classical + PQ baseline).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NegotiatedResult {
    pub version: String,
    pub group: String,
    pub suite: String,
    pub offered_family: OfferedFamily,
}

/// Which round-trip this belongs to: we do a *baseline* (classical only) then
/// a PQ-only offering round-trip (plan 04 "offering policy").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferedFamily {
    ClassicalBaseline,
    PqOnly,
    Both,
}

/// Redacted cert facts (plan 04). We do NOT store full chains in the graph —
/// only the leaf SPKI SHA-256, subject/issuer, signature algorithm, validity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertFacts {
    pub sig_alg: String,
    pub issuer: String,
    pub subject: String,
    /// Leaf SPKI SHA-256 (hex).
    pub leaf_spki_sha256: String,
    pub chain_depth: u32,
    /// ISO-8601 [start, end].
    pub validity_start: String,
    pub validity_end: String,
}
