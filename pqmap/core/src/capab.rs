//! Capability + grade primitives shared by runtime inference (03), the KB
//! matrix and scoring (07).

use serde::{Deserialize, Serialize};

/// A grade on an axis: `A..=F`, `F−`/`D−`-style minors, `Na` for not-applicable,
/// or `Unknown` which is the first-class "not scored (N)" value (plan 07).
///
/// `Unknown` is deliberately distinct from a low grade: counting `Unknown` as a
/// neutral grade silently inflates readiness, which is forbidden (plan 07).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grade {
    A,
    AMinus,
    B,
    BPlus,
    BMinus,
    C,
    CMinus,
    D,
    DMinus,
    F,
    /// Not scored — we do not have enough information (plan 07 "N").
    Na,
    /// Unknown — prefer this over guessing. Distinct from `Na` (no cert / N/A in
    /// scope) in display.
    Unknown,
}

impl Grade {
    /// Numeric rank for ordering/worst-edge selection. `Unknown`/`Na` sort to
    /// the very end (they are not "bad", they are "unknown").
    pub fn rank(&self) -> u8 {
        match self {
            Grade::A => 0,
            Grade::AMinus => 1,
            Grade::BPlus => 2,
            Grade::B => 3,
            Grade::BMinus => 4,
            Grade::C => 5,
            Grade::CMinus => 6,
            Grade::D => 7,
            Grade::DMinus => 8,
            Grade::F => 9,
            Grade::Na => 10,
            Grade::Unknown => 11,
        }
    }

    /// Whether this grade is a real, scored (non-`Unknown`, non-`Na`) grade.
    pub fn scored(&self) -> bool {
        !matches!(self, Grade::Na | Grade::Unknown)
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Grade::A => "A",
            Grade::AMinus => "A-",
            Grade::BPlus => "B+",
            Grade::B => "B",
            Grade::BMinus => "B-",
            Grade::C => "C",
            Grade::CMinus => "C-",
            Grade::D => "D",
            Grade::DMinus => "D-",
            Grade::F => "F",
            Grade::Na => "N/A",
            Grade::Unknown => "N",
        };
        f.write_str(s)
    }
}

/// The four-state PQ capability set per axis (plan 03/07):
/// `pq-negotiated` > `pq-enabled` > `pq-capable` > (`pq-unavailable`, `pq-unknown`).
/// `pq-negotiated` may only be asserted when a live probe actually observed it
/// (plan 04). `pq-unknown` is preferred over guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PqAxisState {
    PqNegotiated,
    PqEnabled,
    PqCapable,
    PqUnavailable,
    PqUnknown,
}

impl PqAxisState {
    /// Ordering: `Unknown` (0) < `Unavailable` (1) < `Capable` (2) < `Enabled` (3)
    /// < `Negotiated` (4).
    pub fn strength(&self) -> u8 {
        match self {
            PqAxisState::PqUnknown => 0,
            PqAxisState::PqUnavailable => 1,
            PqAxisState::PqCapable => 2,
            PqAxisState::PqEnabled => 3,
            PqAxisState::PqNegotiated => 4,
        }
    }
}

/// Provenance of an evidence/KB item (plan 03): a `source_url` + `as_of` so a
/// stale claim is provably stale. A row whose `as_of` is stale or whose
/// `source_url` is unreachable resolves to `pq-unknown` (not a stale `true`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source_url: String,
    /// ISO-8601 date the row was last verified.
    pub as_of: String,
}
