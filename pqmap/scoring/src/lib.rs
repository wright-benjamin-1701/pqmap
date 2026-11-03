//! `pq-scoring` — the two-axis quantum scoring engine + remediation ladder
//! (plans 06 & 07).
//!
//! Two pure, testable entry points:
//!
//! - [`score_graph`] — graph → per-edge assessments + `CompositeScore` (07).
//! - [`remediation::evaluate`] — edge → lowest applicable `Rung` + a
//!   `Finding` that is `verify_gating()`-clean (06).
//!
//! Anti-gaming (plan 07): grades are **derived, not stored**. A stored
//! `pq` field that disagrees with the derived value is surfaced (see
//! `engine::stored_vs_derived`). `N` (`Grade::Unknown`) never counts as a
//! neutral grade; composites state how many edges were `N` and mark
//! `incomplete` whenever coverage is below threshold or any edge is `N`.

pub mod engine;
pub mod remediation;
pub mod snippets;

pub use engine::{assess_edge, score_edges, score_graph, ScoredEdges};
pub use remediation::{evaluate, LadderInput, remediate_confidentiality};
