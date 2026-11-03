//! Two-axis quantum scoring types (plan 07).
//!
//! Grades are **derived, never stored** (plan 07 anti-gaming). The `pq` field
//! on `NetworkEdge` is the cache of the derived assessment; a re-load recomputes
//! from `handshake` + `tls_stack` + `misleading_code` and the cache is only
//! consulted if derivation is unavailable (anti-gaming assertion: stored vs.
//! derived must agree, else it is surfaced).

use serde::{Deserialize, Serialize};

use crate::capab::{Grade, PqAxisState, Provenance};

/// Per-edge assessment (plan 07).
///
/// - `confidentiality` — KEM / key-agreement axis (threat: HNDL).
/// - `authentication`  — signatures/certificate axis (threat: forge/impersonate).
/// - `crypto_agility`  — how hard to move this edge to PQ (plan 06 rung).
/// - `states`          — the four-state per-axis (plan 03/07).
/// - `detail`          — human explanation (anti-gaming: shown in the UI).
/// - `evidence`        — the KB row / probe id / config finding that determined
///                       this grade (anti-gaming: no opaque numbers, plan 07).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAssessment {
    pub confidentiality: Grade,
    pub authentication: Grade,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_agility: Option<Grade>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub states: Option<PqStates>,
    /// Human explanation.
    pub detail: String,
    /// References into the edge's evidence / KB / probe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    /// Provenance of the KB row / policy that determined the grade.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// Whether the edge was actually *scored* (vs. N/Unknown).
    #[serde(default = "default_scored")]
    pub scored: bool,
}

fn default_scored() -> bool {
    true
}

/// Per-axis four-state set (plan 03/07).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqStates {
    pub confidentiality: PqAxisState,
    pub authentication: PqAxisState,
}

impl PqAssessment {
    /// A not-scored assessment (plan 07): prefer `N` over a guessed grade.
    pub fn not_scored(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        PqAssessment {
            confidentiality: Grade::Unknown,
            authentication: Grade::Unknown,
            crypto_agility: None,
            states: None,
            detail,
            evidence_refs: vec![],
            provenance: None,
            scored: false,
        }
    }
}

/// Composite score for a graph (plan 07).
///
/// `INCOMPLETE` when `coverage < 0.8` or there are N-edits — the badge MUST
/// never be cleaner than the data supports.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompositeScore {
    pub confidentiality: Grade,
    pub authentication: Grade,
    pub crypto_agility: Grade,
    /// 0..1
    pub coverage: f32,
    /// Number of unscored (N) edges (plan 07 MUST state this).
    pub unscored: u32,
    /// 0..1 overall readiness (weighted, subject to coverage).
    pub readiness: f32,
    /// `true` when `coverage < threshold` or `unscored > 0`.
    pub incomplete: bool,
    /// Number of edges that *were* scored into the composite.
    pub scored_edges: u32,
    /// Number of edges excluded from scoring (low confidence / N).
    pub excluded_edges: u32,
    /// The threshold at which `incomplete` flips.
    pub coverage_threshold: f32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_edge: Vec<String>,
}

impl CompositeScore {
    /// Whether we should present as "INCOMPLETE" (plan 07 anti-gaming).
    pub fn presents_as_incomplete(&self) -> bool {
        self.incomplete
    }
}

/// Weights for `readiness` (plan 07: confidentiality 0.5, auth 0.35, agility 0.15).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ScoreWeights {
    pub confidentiality: f32,
    pub authentication: f32,
    pub crypto_agility: f32,
    /// Minimum `coverage` before the composite is *trusted*.
    #[serde(default = "default_coverage_threshold")]
    pub coverage_threshold: f32,
}

impl ScoreWeights {
    pub fn default_weights() -> Self {
        Self {
            confidentiality: 0.5,
            authentication: 0.35,
            crypto_agility: 0.15,
            coverage_threshold: 0.8,
        }
    }
}

fn default_coverage_threshold() -> f32 {
    0.8
}
