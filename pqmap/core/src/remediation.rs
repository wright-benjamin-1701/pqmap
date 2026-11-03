//! Remediation types (plan 06).
//!
//! The ladder has four rungs of increasing invasiveness:
//!   1 — dependency bump (PR)
//!   2 — config flip (PR)
//!   3 — IaC change (PR, add a PQ-terminating layer)
//!   4 — PQC Gateway sidecar deploy spec
//!
//! A finding at rung N MUST cite evidence that rungs < N are inapplicable
//! (plan 06 "every rung is gated").

use serde::{Deserialize, Serialize};

use crate::EdgeId;

/// One of the four remediation rungs (plan 06).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    R1Dependency,
    R2Config,
    R3Iac,
    R4Gateway,
}

impl Rung {
    pub fn label(&self) -> &'static str {
        match self {
            Rung::R1Dependency => "Rung 1 — Dependency upgrades",
            Rung::R2Config => "Rung 2 — Config flips",
            Rung::R3Iac => "Rung 3 — Infrastructure (IaC)",
            Rung::R4Gateway => "Rung 4 — PQC Gateway sidecar",
        }
    }

    pub fn ordinal(&self) -> u8 {
        match self {
            Rung::R1Dependency => 1,
            Rung::R2Config => 2,
            Rung::R3Iac => 3,
            Rung::R4Gateway => 4,
        }
    }
}

impl std::fmt::Display for Rung {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A remediation finding for one edge, at a specific rung (plan 06 emit format).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub edge_id: EdgeId,
    /// The deficiency (axis + state), short human label.
    pub deficiency: String,
    /// Which axis (conf/auth/agility) was deficient.
    pub axis: FindingAxis,
    /// The rung selected.
    pub rung: Rung,
    /// Human rationale.
    pub rationale: String,
    /// The concrete change (e.g. a diff summary, dep name, config block).
    pub change: String,
    /// Which lower rungs were attempted / why they fail (plan 06 gating).
    /// If `rung > R1` this MUST be non-empty and explain each inapplicability.
    pub lower_rungs_ruled_out: Vec<RungRuledOut>,
    /// Tests the fix should pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests: Option<String>,
    /// Rollback instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<String>,
    /// Confidence 0..1 in the rung choice.
    #[serde(default = "default_finding_conf")]
    pub confidence: f32,
    /// `true` when this finding is a *propose-only* change (06: PRs are
    /// proposals; dry-run by default; never auto-merge).
    #[serde(default = "default_true")]
    pub dry_run_default: bool,
    /// `true` when the change is idempotent and reversible (06 safety).
    #[serde(default = "default_true")]
    pub idempotent: bool,
    /// `false` for auto-applicable changes (plan 06: no auto-apply by default).
    #[serde(default = "default_false_autoapply")]
    pub auto_applicable: bool,
    /// Runtime-specific remediation snippets (copy-pasteable code).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snippets: Vec<RemediationSnippet>,
}

fn default_finding_conf() -> f32 {
    0.5
}
fn default_true() -> bool {
    true
}
fn default_false_autoapply() -> bool {
    false
}

/// Records why a given lower rung was deemed inapplicable (plan 06 gating).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RungRuledOut {
    pub rung: Rung,
    /// Why it does not apply (evidence, KB row, or config absence).
    pub reason: String,
}

impl Finding {
    /// A finding that MUST have lower rungs ruled out (plan 06 gating).
    /// Enforced: rung 2 requires rung 1 ruled out; rung 3 requires 1+2; rung 4
    /// requires 1+2+3.
    pub fn verify_gating(&self) -> Result<(), String> {
        match self.rung {
            Rung::R1Dependency => Ok(()),
            Rung::R2Config => self.requires(&[Rung::R1Dependency][..]),
            Rung::R3Iac => self.requires(&[Rung::R1Dependency, Rung::R2Config][..]),
            Rung::R4Gateway => self.requires(
                &[Rung::R1Dependency, Rung::R2Config, Rung::R3Iac][..],
            ),
        }
    }

    fn requires(&self, required: &[Rung]) -> Result<(), String> {
        let mut missing = Vec::new();
        for r in required {
            if !self
                .lower_rungs_ruled_out
                .iter()
                .any(|ro| ro.rung == *r)
            {
                missing.push(r.label());
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Plan 06 gating violated: missing ruling-out for {}",
                missing.join(", ")
            ))
        }
    }
}

/// The full remediation plan for one repo (08 #1 "loop proof").
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RemediationPlan {
    /// Findings ordered by rung (lowest first).
    pub findings: Vec<Finding>,
    /// Whether this is a dry-run (06: never auto-apply by default).
    #[serde(default = "default_true")]
    pub dry_run: bool,
    /// ISO timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
}

/// A one-line summary of a finding, for CLI output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingSummary {
    pub edge_id: String,
    pub axis: FindingAxis,
    pub deficiency: String,
    pub rung: Rung,
    pub change: String,
    pub confidence: f32,
    pub dry_run: bool,
}

impl FindingSummary {
    pub fn from(f: &Finding) -> Self {
        Self {
            edge_id: f.edge_id.to_string(),
            axis: f.axis,
            deficiency: f.deficiency.clone(),
            rung: f.rung,
            change: f.change.clone(),
            confidence: f.confidence,
            dry_run: f.dry_run_default,
        }
    }
}

/// The axis axis (07) a finding addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingAxis {
    Confidentiality,
    Authentication,
    CryptoAgility,
}

impl FindingAxis {
    pub fn label(&self) -> &'static str {
        match self {
            FindingAxis::Confidentiality => "confidentiality",
            FindingAxis::Authentication => "authentication",
            FindingAxis::CryptoAgility => "crypto-agility",
        }
    }
}

/// The kind of remediation snippet (plan 06 extension).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnippetKind {
    DependencyUpgrade,
    ConfigChange,
    DockerfileChange,
    ShellCommand,
    IaCChange,
}

/// A copy-pasteable remediation snippet for a specific runtime/framework.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemediationSnippet {
    pub title: String,
    /// Free-form language hint for syntax highlighting: "csharp", "dockerfile",
    /// "hcl", "nginx", "yaml", "toml", "go", "java", "javascript", "python", etc.
    pub language: String,
    pub code: String,
    pub kind: SnippetKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
}
