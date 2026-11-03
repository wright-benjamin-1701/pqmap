//! `pq-core` — the canonical, language-neutral data model for the pqmap control
//! plane (plan 01).
//!
//! The unit of analysis is a **network edge** (`NetworkEdge`), not a function
//! call. Static analysis (02), runtime inference (03), live probing (04),
//! infrastructure detection (05) and scoring (07) all *annotate the same edge
//! record*. `EndpointGraph` is the persistent artifact the SaaS diffs over time.
//!
//! Everything here is plain data (derive Serialize/Deserialize) so the graph is
//! emitted to JSON / SARIF / CycloneDX downstream and shared verbatim with the
//! .NET SaaS API and the TypeScript `packages/graph` package. Nothing in this
//! crate performs I/O.

use serde::{Deserialize, Serialize};

mod capab;
mod edge;
mod graph;
mod handshake;
mod remediation;
mod runtime;
mod sarif;
mod scoring;

pub use capab::*;
pub use edge::*;
pub use graph::*;
pub use handshake::*;
pub use remediation::*;
pub use runtime::*;
pub use sarif::*;
pub use scoring::*;

/// Stable identity of a discovered edge: a hash of `(source, dest, protocol)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeId(pub String);

impl std::fmt::Display for EdgeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl From<&str> for EdgeId {
    fn from(s: &str) -> Self {
        EdgeId(s.to_string())
    }
}

impl From<String> for EdgeId {
    fn from(s: String) -> Self {
        EdgeId(s)
    }
}

/// Deterministically compute an `EdgeId` from (source, dest, protocol) using
/// SHA-256. Stable across runs (plan 01 / 08 #7 reproducibility).
pub fn edge_id(source: &SourceRef, dest: &DestinationRef, protocol: &Protocol) -> EdgeId {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(source.key().as_bytes());
    h.update(b"|");
    h.update(dest.key().as_bytes());
    h.update(b"|");
    h.update(std::any::type_name::<Protocol>() /* tag stable */ .as_bytes());
    // Use the serde canonical serialization of the protocol tag for stability.
    match protocol {
        Protocol::Https => h.update(b"https"),
        Protocol::Http2 => h.update(b"http2"),
        Protocol::Http3 => h.update(b"http3"),
        Protocol::Wss => h.update(b"wss"),
        Protocol::Ws => h.update(b"ws"),
        Protocol::Grpc => h.update(b"grpc"),
        Protocol::Postgres => h.update(b"postgres"),
        Protocol::Mqtt => h.update(b"mqtt"),
        Protocol::Smtp => h.update(b"smtp"),
        Protocol::Tcp => h.update(b"tcp"),
        Protocol::Custom => h.update(b"custom"),
    }
    let digest = h.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    EdgeId(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_a() -> SourceRef {
        SourceRef::Code {
            file: "src/app.py".into(),
            line: 9,
            col: 1,
            symbol: "requests.get".into(),
            language: LanguageTag::Python,
        }
    }

    fn dest_a() -> DestinationRef {
        DestinationRef::ResolvedTarget {
            host: "api.stripe.com".into(),
            port: 443,
            scheme: "https".into(),
        }
    }

    #[test]
    fn edge_id_determinism() {
        let id1 = edge_id(&source_a(), &dest_a(), &Protocol::Https);
        let id2 = edge_id(&source_a(), &dest_a(), &Protocol::Https);
        assert_eq!(id1, id2, "same inputs must produce same EdgeId");
    }

    #[test]
    fn edge_id_uniqueness() {
        let id1 = edge_id(&source_a(), &dest_a(), &Protocol::Https);
        let other_dest = DestinationRef::ResolvedTarget {
            host: "api.example.com".into(),
            port: 443,
            scheme: "https".into(),
        };
        let id2 = edge_id(&source_a(), &other_dest, &Protocol::Https);
        assert_ne!(id1, id2, "different inputs must produce different EdgeIds");
    }

    #[test]
    fn network_edge_json_roundtrip() {
        let e = NetworkEdge {
            id: edge_id(&source_a(), &dest_a(), &Protocol::Https),
            protocol: Protocol::Https,
            direction: Direction::Outbound,
            source: source_a(),
            destination: dest_a(),
            framework: Some("requests".into()),
            tls_provider: None,
            upstream_owner: None,
            runtime: None,
            tls_stack: None,
            misleading_code: None,
            handshake: None,
            pq: None,
            confidence: 0.9,
            evidence: vec![],
            resolution: vec![],
        };
        let json = serde_json::to_string(&e).unwrap();
        let e2: NetworkEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(e.id, e2.id);
        assert_eq!(e.protocol, e2.protocol);
    }

    #[test]
    fn source_ref_key_format() {
        let s = source_a();
        let k = s.key();
        assert!(k.contains("src/app.py"), "key should contain file path: {k}");
    }
}
