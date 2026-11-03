//! The remediation ladder (plan 06).
//!
//! Plan 06 principle: *"Apply the fix at the lowest-risk, correct layer,
//! following a ladder of increasing invasiveness… Every rung is gated: the
//! system MUST prove the lower rung is inapplicable (evidence in the graph)
//! before recommending a higher rung."*
//!
//! The ladder (increasing invasiveness):
//!   R1 — dependency bump (e.g. Node 20→22, `net8`→`net10`, base image)
//!   R2 — config flip (ciphers / `TlsSuites` / `ssl_conf_command`)
//!   R3 — infrastructure / IaC (add a PQ-terminating layer in front)
//!   R4 — PQC Gateway sidecar (deploy spec; no app change)
//!
//! This evaluator is a **pure function**: given an edge (its TLS owner,
//! whether infra terminates first, the KB states, and the available evidence)
//! it selects the lowest applicable rung and returns a `Finding` that cites
//! why each lower rung was ruled out (the `lower_rungs_ruled_out` gating).
//!
//! Plan 06 safety: findings are *proposals* — `dry_run_default = true`,
//! `auto_applicable = false`, and every finding is `verify_gating()`-clean.
//!
//! ## Loop proof (plan 08 acceptance #1)
//!
//! An edge whose code is classical and which sits **behind an ALB** (plan 05
//! `misleading_code`) MUST select R3/R4 (infra), **not** a Python lib bump —
//! because a dependency bump (R1) cannot change what the ALB negotiates. The
//! `loop_proof` test asserts exactly this.

use pq_core::{
    Finding, FindingAxis, NetworkEdge, PqAxisState, Rung, RungRuledOut, TlsOwner, Grade,
};

use crate::snippets;

/// Inputs the evaluator needs from the graph. We read directly off the edge so
/// the CLI doesn't have to assemble them.
pub struct LadderInput<'a> {
    pub edge: &'a NetworkEdge,
    /// The axis we're remedying (confidentiality is the primary V1 axis).
    pub axis: FindingAxis,
}

/// Select the lowest applicable rung and build a gated `Finding`.
///
/// Returns `None` when the edge is already PQ (no deficiency to remediate) or
/// is not scoreable (N). Otherwise returns a `Finding` that passes
/// `Finding::verify_gating()`.
pub fn evaluate(input: LadderInput<'_>) -> Option<Finding> {
    let e = input.edge;

    // If the edge is already PQ-negotiated or PQ-enabled on the axis, there is
    // nothing to remediate.
    if is_pq_on_axis(e, &input.axis) {
        return None;
    }

    // If we cannot score the axis at all (N / unknown), we must not recommend a
    // rung (plan 06: a higher rung is only valid with lower rung ruled out; we
    // can't prove inapplicability without a known deficiency). Return None.
    let Some(state) = axis_state(e, &input.axis) else {
        return None;
    };
    if state == PqAxisState::PqUnknown {
        return None;
    }

    let rung = choose_rung(e);
    Some(build_finding(e, input.axis, state, rung))
}

/// Whether the edge is already PQ on the axis (i.e. no remediation needed).
fn is_pq_on_axis(e: &NetworkEdge, axis: &FindingAxis) -> bool {
    // A live negotiation is the strongest "done" signal for the KEM axis.
    if *axis == FindingAxis::Confidentiality
        && e.handshake.as_ref().is_some_and(|h| h.server_negotiated_pq)
    {
        return true;
    }
    // A PQ signature in the observed chain (ML-DSA / SLH-DSA) means the
    // authentication axis is done.
    if *axis == FindingAxis::Authentication
        && e.handshake
            .as_ref()
            .and_then(|h| h.cert.as_ref())
            .is_some_and(|c| {
                let u = c.sig_alg.to_uppercase();
                u.contains("ML-DSA") || u.contains("SLH-DSA") || u.contains("MLDSA") || u.contains("SLHDSA")
            })
    {
        return true;
    }
    // A static "enabled"/"negotiated" stack state means the axis is covered.
    // "capable-but-not-enabled" is NOT done: it needs a Rung-2 config flip.
    match axis {
        FindingAxis::Confidentiality => e
            .tls_stack
            .as_ref()
            .is_some_and(|s| s.pq_kem.state.strength() >= PqAxisState::PqEnabled.strength()),
        FindingAxis::Authentication => e
            .tls_stack
            .as_ref()
            .is_some_and(|s| s.pq_sig.state.strength() >= PqAxisState::PqEnabled.strength()),
        FindingAxis::CryptoAgility => false,
    }
}

fn axis_state(e: &NetworkEdge, axis: &FindingAxis) -> Option<PqAxisState> {
    let s = e.tls_stack.as_ref()?;
    match axis {
        FindingAxis::Confidentiality => Some(s.pq_kem.state),
        FindingAxis::Authentication => Some(s.pq_sig.state),
        FindingAxis::CryptoAgility => None,
    }
}

/// Plan 06 ladder decision. The *correct layer* is determined by who actually
/// terminates TLS (plan 01 invariant 2 / plan 05 topology):
///
/// - If **infra** is the outermost TLS owner (`tls_provider` is `Infra`, or a
///   `misleading_code` finding names a terminator), R1 and R2 are inapplicable —
///   a dependency bump or app-config flip cannot change what the LB negotiates.
///   ⇒ R3 (IaC) if an infra component can be changed, else R4 (Gateway).
/// - Otherwise the owner is **code/library/runtime** ⇒ R1 (dependency) first,
///   R2 (config) if the runtime already supports PQ but it's not enabled.
fn choose_rung(e: &NetworkEdge) -> Rung {
    let owned_by_infra = e
        .tls_provider
        .as_ref()
        .is_some_and(|o| o.is_infra())
        || e.misleading_code.is_some();

    if owned_by_infra {
        // Plan 05: the outermost infra component wins. If it's a known
        // PQ-terminating infra (CloudFront / Cloudflare edge) we'd already have
        // a PQ edge; so the deficiency implies a classical LB (ALB) ⇒ add a PQ
        // layer in front (R3) or a Gateway (R4). Prefer R3 (IaC, least invasive
        // infra change).
        return Rung::R3Iac;
    }

    // Code / library / runtime owner. Prefer the lowest rung that can work.
    // R1 applies when the runtime's version can be bumped to a PQ-capable one
    // (the KB stack row exists and is below a PQ row). R2 when the current
    // runtime is already PQ-capable (stack = capable) but not enabled.
    if let Some(s) = e.tls_stack.as_ref() {
        if s.pq_kem.state == PqAxisState::PqCapable || s.pq_kem.state == PqAxisState::PqEnabled {
            return Rung::R2Config;
        }
        // Below PQ-capable (classical) → a version/dependency bump is the fix.
        return Rung::R1Dependency;
    }
    // No stack info. The most conservative correct-layer answer for a code edge
    // with an unresolved runtime is a dependency bump (R1) — but we gate it.
    Rung::R1Dependency
}

/// Build a fully-gated `Finding` for the chosen rung (plan 06).
fn build_finding(
    e: &NetworkEdge,
    axis: FindingAxis,
    state: PqAxisState,
    rung: Rung,
) -> Finding {
    let deficiency = format!(
        "{} is '{}' (not PQ) for this edge",
        axis.label(),
        state_to_str(state)
    );
    let (rationale, change, lower) = match rung {
        Rung::R1Dependency => (
            format!(
                "Runtime/library below a PQ-capable version; a dependency or \
                 base-image bump reaches PQ with no infra change."
            ),
            "bump dependency / base image to a PQ-capable version (PR, dry-run)".to_string(),
            vec![],
        ),
        Rung::R2Config => (
            "Runtime is already PQ-capable but PQ groups are not enabled.".to_string(),
            "flip app/ framework config to enable PQ groups (PR, dry-run)".to_string(),
            vec![RungRuledOut {
                rung: Rung::R1Dependency,
                reason: "the selected runtime version is already PQ-capable; a bump is a no-op".to_string(),
            }],
        ),
        Rung::R3Iac => (
            format!(
                "{} terminates TLS before the application code (code owner recorded as \
                 upstream); a code-level PQ change has no effect.",
                e.misleading_code
                    .as_ref()
                    .map(|m| m.terminating_component.clone())
                    .or_else(|| e.tls_provider.as_ref().and_then(owner_component))
                    .unwrap_or_else(|| "an upstream infrastructure component".to_string())
            ),
            "add a PQ-terminating layer in front via IaC (ALB→PQ LB / CF edge, PR)".to_string(),
            vec![
                RungRuledOut {
                    rung: Rung::R1Dependency,
                    reason: infra_ruling(e).to_string(),
                },
                RungRuledOut {
                    rung: Rung::R2Config,
                    reason: "the app's config cannot override the outermost terminator".to_string(),
                },
            ],
        ),
        Rung::R4Gateway => (
            "No code, config, or IaC layer above the app is PQ-terminating.".to_string(),
            "deploy a PQC Gateway sidecar in front (Helm/Terraform deploy spec)".to_string(),
            vec![
                RungRuledOut {
                    rung: Rung::R1Dependency,
                    reason: infra_ruling(e).to_string(),
                },
                RungRuledOut {
                    rung: Rung::R2Config,
                    reason: "the app's config cannot override the outermost terminator".to_string(),
                },
                RungRuledOut {
                    rung: Rung::R3Iac,
                    reason: "no manageable IaC terminator is present to change".to_string(),
                },
            ],
        ),
    };

    let snips = snippets::generate(rung, e, axis);

    Finding {
        edge_id: e.id.clone(),
        deficiency,
        axis,
        rung,
        rationale,
        change,
        lower_rungs_ruled_out: lower,
        tests: Some("integration/tls.spec.ts asserts pq-negotiated".to_string()),
        rollback: Some(format!("revert the {rung} change / redeploy previous image")),
        confidence: e.confidence,
        dry_run_default: true,
        idempotent: true,
        auto_applicable: false,
        snippets: snips,
    }
}

fn owner_component(o: &TlsOwner) -> Option<String> {
    match o {
        TlsOwner::Infra { component } => Some(component.clone()),
        _ => None,
    }
}

fn infra_ruling(e: &NetworkEdge) -> &str {
    static NOTE: &str = "infrastructure terminates TLS first, so a dependency bump cannot change the negotiated group";
    // (A `misleading_code` note, if present, would be the stronger citation.)
    if e.misleading_code.is_some() {
        return NOTE;
    }
    NOTE
}

fn state_to_str(s: PqAxisState) -> &'static str {
    match s {
        PqAxisState::PqNegotiated => "pq-negotiated",
        PqAxisState::PqEnabled => "pq-enabled",
        PqAxisState::PqCapable => "pq-capable",
        PqAxisState::PqUnavailable => "pq-unavailable",
        PqAxisState::PqUnknown => "pq-unknown",
    }
}

/// `crypto_agility` grade (plan 07 "grade from Rung position"): Rung 1 → A,
/// Rung 2 → B, Rung 3 → C, Rung 4 → D. Exposed so the scoring engine can
/// derive the meta-axis from the same correct-layer decision the ladder uses.
pub fn agility_from_rung(rung: Rung) -> Grade {
    match rung {
        Rung::R1Dependency => Grade::A,
        Rung::R2Config => Grade::B,
        Rung::R3Iac => Grade::C,
        Rung::R4Gateway => Grade::D,
    }
}

/// The best (lowest) applicable rung for an edge on an axis, if any. Reused by
/// both the `evaluate` gating and the engine's crypto-agility derivation so the
/// two never disagree (plan 06/07 consistency).
pub fn best_rung(e: &NetworkEdge, axis: &FindingAxis) -> Option<Rung> {
    if is_pq_on_axis(e, axis) {
        return None;
    }
    let state = axis_state(e, axis)?;
    if state == PqAxisState::PqUnknown {
        return None;
    }
    Some(choose_rung(e))
}

/// A convenience: evaluate an edge on confidentiality and return a gated
/// finding, if any. Mirrors `pqmap fix`'s default behavior.
pub fn remediate_confidentiality(e: &NetworkEdge) -> Option<Finding> {
    evaluate(LadderInput { edge: e, axis: FindingAxis::Confidentiality })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::{
        edge_id, DestinationRef, Evidence, Grade, MisleadingCode, PqAxisState, Protocol, SourceRef,
        TlsCapability, TlsStack, TlsImplementation,
    };

    fn code_source() -> (SourceRef, DestinationRef) {
        let src = SourceRef::Code {
            file: "app.py".into(),
            line: 10,
            col: 1,
            symbol: "main".into(),
            language: pq_core::LanguageTag::Python,
        };
        let dst = DestinationRef::ResolvedTarget {
            host: "example.com".into(),
            port: 443,
            scheme: "https".into(),
        };
        (src, dst)
    }

    fn cap(state: PqAxisState) -> TlsCapability {
        TlsCapability {
            state,
            groups: vec![],
            source_url: "https://example".into(),
            as_of: "2025-01-01".into(),
        }
    }

    /// A python app, classical runtime, owner = code.
    fn edge_code_owner(state: PqAxisState, misleading: Option<MisleadingCode>, provider_infra: bool) -> NetworkEdge {
        let (src, dst) = code_source();
        let id = edge_id(&src, &dst, &Protocol::Https);
        let stack = TlsStack {
            impl_kind: TlsImplementation::OpenSSL,
            version: Some("3.0".into()),
            os: Some("linux".into()),
            pq_kem: cap(state),
            pq_sig: cap(PqAxisState::PqUnavailable),
            provenance: pq_core::Provenance { source_url: "u".into(), as_of: "d".into() },
            evidence: vec![],
        };
        NetworkEdge {
            id,
            protocol: Protocol::Https,
            direction: pq_core::Direction::Outbound,
            source: src,
            destination: dst,
            framework: Some("fastapi".into()),
            tls_provider: if provider_infra {
                Some(TlsOwner::Infra { component: "alb".into() })
            } else {
                Some(TlsOwner::Library { name: "requests".into(), version: None })
            },
            upstream_owner: None,
            runtime: None,
            tls_stack: Some(stack),
            misleading_code: misleading,
            handshake: None,
            pq: None,
            confidence: 0.9,
            evidence: vec![Evidence::Kb { row_id: "r".into(), source_url: "u".into(), as_of: "d".into() }],
            resolution: vec![],
        }
    }

    #[test]
    fn infra_first_is_rung3_not_python_bump() {
        // Plan 08 loop proof: python app behind an ALB → R3 (not R1).
        let e = edge_code_owner(
            PqAxisState::PqUnavailable,
            Some(MisleadingCode {
                note: "ALB terminates first".into(),
                terminating_component: "aws-alb".into(),
            }),
            true,
        );
        let f = remediate_confidentiality(&e).expect("a finding");
        assert_eq!(f.rung, Rung::R3Iac, "behind an infra terminator the correct layer is IaC, not a lib bump");
        f.verify_gating().expect("gate clean");
        // R1 and R2 must be ruled out.
        assert!(f.lower_rungs_ruled_out.iter().any(|r| r.rung == Rung::R1Dependency));
        assert!(f.lower_rungs_ruled_out.iter().any(|r| r.rung == Rung::R2Config));
        assert!(!f.snippets.is_empty(), "finding must include remediation snippets");
    }

    #[test]
    fn classical_code_is_rung1() {
        let e = edge_code_owner(PqAxisState::PqUnavailable, None, false);
        let f = remediate_confidentiality(&e).expect("a finding");
        assert_eq!(f.rung, Rung::R1Dependency, "classical code-owned edge → dependency bump first");
        f.verify_gating().expect("gate clean");
        assert!(f.dry_run_default);
        assert!(!f.auto_applicable);
        assert!(!f.snippets.is_empty(), "finding must include remediation snippets");
    }

    #[test]
    fn capable_but_disabled_is_rung2() {
        let e = edge_code_owner(PqAxisState::PqCapable, None, false);
        let f = remediate_confidentiality(&e).expect("a finding");
        assert_eq!(f.rung, Rung::R2Config, "already PQ-capable → config flip enables it");
        f.verify_gating().expect("gate clean");
        assert!(f.lower_rungs_ruled_out.iter().any(|r| r.rung == Rung::R1Dependency), "must rule out R1");
        assert!(!f.snippets.is_empty(), "finding must include remediation snippets");
    }

    #[test]
    fn pq_edge_has_no_finding() {
        let mut e = edge_code_owner(PqAxisState::PqNegotiated, None, false);
        e.handshake = Some(pq_core::HandshakeFacts {
            at: "t".into(), tls_versions: vec![], negotiated: vec![], offered_groups: vec![],
            server_negotiated_pq: true, cert: None, alpn: vec![], quic: false, ja3_server: None,
            ja4_server: None, rtt_ms: None, server_requested_client_cert: false,
            report_id: "r".into(), evidence: vec![],
        });
        assert!(remediate_confidentiality(&e).is_none(), "a PQ-negotiated edge needs no remediation");
    }

    #[test]
    fn unknown_is_unscored_no_finding() {
        let e = edge_code_owner(PqAxisState::PqUnknown, None, false);
        assert!(remediate_confidentiality(&e).is_none(), "pq-unknown must not drive a rung (prefer N, gate)");
    }

    #[allow(dead_code)]
    fn _typecheck_grade() {
        let _ = Grade::A;
    }
}
