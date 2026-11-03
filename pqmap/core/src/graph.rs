//! The endpoint graph + node types (plan 01).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::capab::Provenance;
use crate::edge::{InputHash, NetworkEdge};
use crate::scoring::CompositeScore;

/// An `EndpointGraph` is `(nodes, edges)` + the score + provenance of the scan.
///
/// Stored on disk as `pqmap.graph.json`. Versioned. The graph is the persistent
/// artifact the SaaS diffs over time ("drift" view); we retain a hash of inputs
/// so we can prove two graphs are comparable (plan 01 invariants).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EndpointGraph {
    /// Schema version so consumers can migrate.
    #[serde(default = "default_schema")]
    pub schema: u32,
    pub nodes: BTreeMap<String, GraphNode>,
    pub edges: Vec<NetworkEdge>,
    /// Tree hash of the input files (08 #7 reproducibility).
    pub input_hash: Option<InputHash>,
    /// The KB rows used, embedded with provenance (plan 03 anti-liability).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kb_rows_used: Vec<KbRowUsed>,
    /// The derived composite score (anti-gaming: recomputed on load).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<CompositeScore>,
    /// ISO timestamp of when this graph was produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_at: Option<String>,
}

fn default_schema() -> u32 {
    1
}

impl Provenance {
    /// Helper to build a Provenance from row-like pieces.
    pub fn builder(source_url: impl Into<String>, as_of: impl Into<String>) -> Self {
        Self {
            source_url: source_url.into(),
            as_of: as_of.into(),
        }
    }
}

/// References into KB rows actually used by this scan's scoring (plan 03), each
/// with provenance + as-of (anti-liability: unproven stays unknown).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KbRowUsed {
    pub row_id: String,
    pub source_url: String,
    pub as_of: String,
    /// Edge ids for which this row was the *determining* row.
    pub used_for: Vec<String>,
}

/// A node in the graph: code module / service / infra component / endpoint /
/// browser (plan 01).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GraphNode {
    /// A source-file module / service (code).
    Service {
        name: String,
        language: Option<String>,
        file: Option<String>,
    },
    /// An infrastructure terminator (ALB, CF, nginx, Envoy) (plan 05).
    Infra {
        name: String,
        vendor: String,
        node_kind: String,
        terminates_tls: bool,
    },
    /// A third-party endpoint (Stripe, Postgres, S3) (plan 05).
    Endpoint { name: String, node_kind: String },
    /// The browser, for inbound edges.
    Browser,
}

impl GraphNode {
    /// Human-facing label.
    pub fn label(&self) -> String {
        match self {
            GraphNode::Service { name, .. } => name.clone(),
            GraphNode::Infra { name, .. } => name.clone(),
            GraphNode::Endpoint { name, .. } => name.clone(),
            GraphNode::Browser => "browser".to_string(),
        }
    }
    /// Whether this node is an infra terminator (plan 05).
    pub fn is_infra(&self) -> bool {
        matches!(self, GraphNode::Infra { .. })
    }
}
