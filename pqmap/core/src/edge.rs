//! The network edge record and its reference types (plan 01).

use serde::{Deserialize, Serialize};

use std::fmt;

use crate::{
    handshake::HandshakeFacts,
    runtime::{RuntimeFacts, TlsStack},
    scoring::PqAssessment,
};

/// A single directed network relationship discovered anywhere in the system.
///
/// Invariants (plan 01):
/// 1. Every edge has ≥ 1 evidence item; `confidence < 0.5` edges are flagged
///    `unverified` and excluded from scoring by default.
/// 2. `tls_provider` is a single owner; the outermost infra component wins and
///    the inner one is recorded as `upstream_owner`.
/// 3. The graph contains no secrets (destinations are host:port only).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkEdge {
    pub id: crate::EdgeId,
    pub protocol: Protocol,
    pub direction: Direction,
    pub source: SourceRef,
    pub destination: DestinationRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_provider: Option<TlsOwner>,
    /// Upstream owner (inner terminator) when the outermost infra component
    /// wins (e.g. Kestrel behind an ALB).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_owner: Option<TlsOwner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeFacts>,
    /// The resolved TLS stack from plan 03.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_stack: Option<TlsStack>,
    /// A first-class "misleading code" finding (plan 05).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub misleading_code: Option<MisleadingCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake: Option<HandshakeFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq: Option<PqAssessment>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// Evidence items (plan 01 invariant 1).
    pub evidence: Vec<Evidence>,
    /// Resolution explanation chain (plan 02 `--explain`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution: Vec<ResolutionStep>,
}

fn default_confidence() -> f32 {
    0.5
}

impl NetworkEdge {
    /// Invariant 1: an edge must cite at least one evidence item.
    pub fn has_evidence(&self) -> bool {
        !self.evidence.is_empty()
    }

    /// Invariant 1: low-confidence (unverified) edges are excluded from scoring.
    pub fn unverified(&self) -> bool {
        self.confidence < 0.5
    }
}

/// A one-line, human-readable step in the resolution chain (what matched, where,
/// at what confidence). Emitted by `pqmap scan --explain <edge-id>`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolutionStep {
    pub what: String,
    pub detail: String,
    /// 0..1 contribution to the edge's overall confidence.
    pub confidence: f32,
}

/// A "misleading code" finding: the code *appears* to own TLS, but an
/// infrastructure component terminates it first, so a code-level PQ change has
/// no effect (plan 05, the differentiator).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MisleadingCode {
    pub note: String,
    pub terminating_component: String,
}

/// Protocol family of the edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Https,
    Http2,
    Http3,
    Wss,
    Ws,
    Grpc,
    Postgres,
    Mqtt,
    Smtp,
    Tcp,
    Custom,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Protocol::Https => "https",
            Protocol::Http2 => "http2",
            Protocol::Http3 => "http3",
            Protocol::Wss => "wss",
            Protocol::Ws => "ws",
            Protocol::Grpc => "grpc",
            Protocol::Postgres => "postgres",
            Protocol::Mqtt => "mqtt",
            Protocol::Smtp => "smtp",
            Protocol::Tcp => "tcp",
            Protocol::Custom => "custom",
        };
        f.write_str(s)
    }
}

impl Protocol {
    /// Parse from its wire string (`https`, `http2`, `wss`, …).
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "https" => Protocol::Https,
            "http2" => Protocol::Http2,
            "http3" => Protocol::Http3,
            "wss" => Protocol::Wss,
            "ws" => Protocol::Ws,
            "grpc" => Protocol::Grpc,
            "postgres" => Protocol::Postgres,
            "mqtt" => Protocol::Mqtt,
            "smtp" => Protocol::Smtp,
            "tcp" => Protocol::Tcp,
            _ => Protocol::Custom,
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Https
    }
}

/// Direction relative to the analyzed application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Where a connection originates. Carries `file:line:col`, symbol and a
/// language tag (plan 01 / 02).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceRef {
    /// A code location: file, line, column, enclosing symbol, language.
    Code {
        file: String,
        line: u32,
        col: u32,
        symbol: String,
        language: LanguageTag,
    },
    /// An infrastructure / service component (plan 05).
    Infra { component: String, component_kind: String },
    /// The browser, for inbound edges from frontend code (plan 00/01).
    Browser,
}

impl SourceRef {
    /// Stable identity used in the edge id hash.
    pub fn key(&self) -> String {
        match self {
            SourceRef::Code {
                file, line, col, ..
            } => format!("code:{}:{}:{}", file, line, col),
            SourceRef::Infra { component, .. } => format!("infra:{}", component),
            SourceRef::Browser => "browser".to_string(),
        }
    }
}

/// A language tag, independent of the target language of this analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageTag {
    Js,
    Ts,
    Csharp,
    Python,
    Go,
    Rust,
    Java,
    Unknown,
}

impl LanguageTag {
    pub fn from_extension(ext: &str) -> LanguageTag {
        match ext {
            "js" | "mjs" | "cjs" => LanguageTag::Js,
            "ts" | "tsx" => LanguageTag::Ts,
            "cs" => LanguageTag::Csharp,
            "py" => LanguageTag::Python,
            "go" => LanguageTag::Go,
            "rs" => LanguageTag::Rust,
            "java" => LanguageTag::Java,
            _ => LanguageTag::Unknown,
        }
    }
}

/// Where a connection is going. Either a resolved target or an unresolved
/// expression (dynamic host), in which case we do not guess (plan 02/03).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DestinationRef {
    ResolvedTarget {
        host: String,
        port: u16,
        scheme: String,
    },
    UnresolvedExpr { expr: String },
}

impl DestinationRef {
    /// Stable identity used in the edge id hash.
    pub fn key(&self) -> String {
        match self {
            DestinationRef::ResolvedTarget { host, port, .. } => {
                format!("target:{}:{}", host, port)
            }
            DestinationRef::UnresolvedExpr { expr } => format!("expr:{}", expr),
        }
    }
}

/// Who actually terminates / owns TLS on this edge (plan 01).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TlsOwner {
    /// Explicit SSLSocket / SslStream / context in code.
    CodeInline { impl_name: String },
    Library { name: String, version: Option<String> },
    /// Node / .NET / JVM default stack.
    Runtime { name: String },
    /// Schannel, SecureTransport, OpenSSL via libcrypto.
    Os { name: String },
    /// ALB, CloudFront, nginx, Envoy, sidecar.
    Infra { component: String },
    Unknown,
}

impl TlsOwner {
    /// A human-friendly label.
    pub fn label(&self) -> String {
        match self {
            TlsOwner::CodeInline { impl_name } => format!("code:{}", impl_name),
            TlsOwner::Library { name, version } => match version {
                Some(v) => format!("{}@{}", name, v),
                None => name.clone(),
            },
            TlsOwner::Runtime { name } => format!("runtime:{}", name),
            TlsOwner::Os { name } => format!("os:{}", name),
            TlsOwner::Infra { component } => format!("infra:{}", component),
            TlsOwner::Unknown => "unknown".to_string(),
        }
    }

    /// Whether this owner is an infrastructure component (outermost).
    pub fn is_infra(&self) -> bool {
        matches!(self, TlsOwner::Infra { .. })
    }
}

/// A redacted, auditable evidence item (plan 01 invariant 1).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    Code {
        file: String,
        line: u32,
        symbol: String,
        matched_api: String,
    },
    Lockfile { file: String, entry: String },
    Iac { file: String, block: String, line: u32 },
    Probe { report_id: String },
    Kb { row_id: String, source_url: String, as_of: String },
    Config { file: String, snippet: String, line: u32 },
}

impl Evidence {
    /// A short human label of this evidence item.
    pub fn label(&self) -> String {
        match self {
            Evidence::Code { file, line, .. } => format!("{}:{}", file, line),
            Evidence::Lockfile { file, entry } => format!("{} ({})", file, entry),
            Evidence::Iac { file, line, .. } => format!("{}:{}", file, line),
            Evidence::Probe { report_id } => format!("probe:{}", report_id),
            Evidence::Kb { row_id, .. } => format!("kb:{}", row_id),
            Evidence::Config { file, line, .. } => format!("{}:{}", file, line),
        }
    }
}

/// The input tree-hash (plan 01 invariants): a hash of the analyzed files +
/// lockfiles proving two graphs are comparable / reproducible (08#7).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputHash {
    /// SHA-256 hex of the concatenated file tree (paths + content, sorted).
    pub sha256: String,
    /// Number of files hashed.
    pub file_count: u64,
    /// Top-level repo root path (for humans).
    pub tree_root: String,
}
