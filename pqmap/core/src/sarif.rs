//! SARIF 2.1.0 output (plan 01 output surface for CI / PR annotations).
//!
//! `SarifDocument::from_edges` converts a set of `NetworkEdge`s into SARIF
//! `results` with rule id = the matched catalog API, source location =
//! `file:line:col`, and the two-axis grades carried in `properties`.

use serde::{Deserialize, Serialize};

use crate::{EdgeId, Evidence, Grade, NetworkEdge, SourceRef};

/// A SARIF 2.1.0 document (the fields we emit).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SarifDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<Run>,
}

/// One `runs` entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<SarifResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tool {
    pub driver: ToolDriver,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolDriver {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ReportedRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportedRule {
    pub id: String,
    pub name: String,
}

/// Per-result `properties`: the two-axis grades + evidence + edge id.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SarifProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_kem_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_sig_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub misleading_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SarifResult {
    pub rule_id: String,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub locations: Vec<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifProperties>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Location {
    pub physical_location: PhysicalLocation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhysicalLocation {
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Region {
    pub start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
}

/// Rule severity from a grade. `F`/`D-`/`D` → error; `C`/`C-` → warning;
/// `B`/`N`/`unknown` → note. (Anti-gaming, plan 07: N is not a "failure".)
pub fn severity_for_grade(g: &Grade) -> &'static str {
    match g {
        Grade::F | Grade::D | Grade::DMinus => "error",
        Grade::C | Grade::CMinus => "warning",
        _ => "note",
    }
}

impl SarifDocument {
    /// Build the document from a set of edges (one per edge with a code location).
    pub fn from_edges(edges: &[NetworkEdge]) -> Self {
        let mut result_set: Vec<SarifResult> = Vec::new();
        let mut rule_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for e in edges {
            let (file, line, col) = match &e.source {
                SourceRef::Code {
                    file,
                    line,
                    col,
                    ..
                } => (file.clone(), *line, *col),
                _ => continue,
            };

            let rule_id = e
                .evidence
                .iter()
                .find_map(|ev| match ev {
                    Evidence::Code { matched_api, .. } => Some(matched_api.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "pqmap.edge".to_string());
            if !rule_ids.insert(rule_id.clone()) {
                // Already seen a result for this rule id.
            }

            let detail = e
                .pq
                .as_ref()
                .map(|p| p.detail.clone())
                .unwrap_or_else(|| "no grade".to_string());

            let worst = e.pq.as_ref().map(|p| {
                if p.confidentiality.rank() >= p.authentication.rank() {
                    p.confidentiality
                } else {
                    p.authentication
                }
            });

            result_set.push(SarifResult {
                rule_id: rule_id.clone(),
                message: SarifMessage {
                    text: detail.clone(),
                    markdown: Some(format!("**PQ edge.** {}", detail)),
                },
                level: worst
                    .map(|g| severity_for_grade(&g).to_string())
                    .or_else(|| Some("note".to_string())),
                kind: Some("open".to_string()),
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation { uri: file },
                        region: Region {
                            start_line: line,
                            start_column: Some(col),
                        },
                    },
                }],
                properties: Some(SarifProperties {
                    edge_id: Some(e.id.to_string()),
                    confidentiality_grade: e
                        .pq
                        .as_ref()
                        .map(|p| p.confidentiality.to_string()),
                    authentication_grade: e
                        .pq
                        .as_ref()
                        .map(|p| p.authentication.to_string()),
                    pq_kem_state: e
                        .pq
                        .as_ref()
                        .and_then(|p| p.states.as_ref())
                        .map(|s| format!("{:?}", s.confidentiality)),
                    pq_sig_state: e
                        .pq
                        .as_ref()
                        .and_then(|p| p.states.as_ref())
                        .map(|s| format!("{:?}", s.authentication)),
                    evidence: Some(e.evidence.iter().map(|ev| ev.label()).collect()),
                    misleading_code: e
                        .misleading_code
                        .as_ref()
                        .map(|mc| format!("{} — {}", mc.terminating_component, mc.note)),
                }),
            });
        }

        let rules: Vec<ReportedRule> = rule_ids
            .into_iter()
            .map(|id| ReportedRule {
                name: id.clone(),
                id,
            })
            .collect();

        SarifDocument {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
                .to_string(),
            version: "2.1.0".to_string(),
            runs: vec![Run {
                tool: Tool {
                    driver: ToolDriver {
                        name: "pqmap".to_string(),
                        version: Some(env!("CARGO_PKG_VERSION").to_string()),
                        rules,
                    },
                },
                results: result_set,
            }],
        }
    }
}

/// A convenience helper to extract the `edge_id` from a serialized property
/// (used by the SaaS when re-hydrating edges).
pub fn parse_edge_id(v: &str) -> Option<EdgeId> {
    Some(EdgeId(v.to_string()))
}
