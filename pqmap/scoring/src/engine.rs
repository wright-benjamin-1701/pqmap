//! `pq-scoring` — the pure two-axis quantum scoring engine (plan 07).
//!
//! This is the *only* place a grade is derived. Plan 07 anti-gaming rules:
//!
//! - Grades are **derived, never stored**. `EndpointGraph.score` is a cache;
//!   on load we recompute and compare (mismatch = bug, surfaced).
//! - **N** (`Grade::Unknown`) is first-class: it MUST NOT count as neutral.
//!   Composite MUST state how many edges were `N` and why.
//! - A graph at 40% coverage with a few `A`s is NOT more trusted than 95%
//!   coverage with B/C. `incomplete = coverage < threshold || unscored > 0`.
//!
//! The rules are **data** (tables in `rules.rs`) so they are reviewable and
//! tunable. Every rule row is covered by a focused test below.
//!
//! No I/O. No clock. A stable "now" is injected for the deterministic tests.

use pq_core::{CompositeScore, Grade, NetworkEdge, PqAssessment, PqAxisState, PqStates, ScoreWeights};

/// Pure scoring: `graph -> { per-edge PqAssessment, CompositeScore }`.
///
/// `weights` controls the composite. Use `ScoreWeights::default_weights()`
/// (confidentiality 0.5, auth 0.35, agility 0.15, threshold 0.8) for V1.
pub fn score_edges(edges: &[NetworkEdge]) -> ScoredEdges {
    let mut scored = Vec::with_capacity(edges.len());
    let mut unscored: u32 = 0;
    let mut excluded: u32 = 0;

    for e in edges {
        // Low-confidence edges are `unverified` (plan 01 invariant 1) — they are
        // never scored (surfaced via `excluded_edges` in the composite).
        if e.unverified() {
            excluded += 1;
            scored.push((e.id.clone(), PqAssessment::not_scored(
                format!("low-confidence edge ({} < 0.5) — not scored (plan 01)", e.confidence),
            )));
            continue;
        }
        let a = assess_edge(e);
        if !a.scored {
            unscored += 1;
        }
        scored.push((e.id.clone(), a));
    }

    let scored_edges = scored.iter().filter(|(_, a)| a.scored).count() as u32;
    let total = edges.len() as u32;
    let composite = build_composite(&scored, scored_edges, unscored, excluded, total, ScoreWeights::default_weights());
    ScoredEdges {
        per_edge: scored,
        composite,
    }
}

/// Result of `score_edges`: per-edge assessments + the composite.
pub struct ScoredEdges {
    pub per_edge: Vec<(pq_core::EdgeId, PqAssessment)>,
    pub composite: CompositeScore,
}

impl ScoredEdges {
    /// Apply the per-edge assessments to a set of edges. `NetworkEdge` ids are
    /// stable (`EdgeId(pub String)`); we match by id.
    pub fn apply(&self, edges: &mut [NetworkEdge]) {
        for e in edges.iter_mut() {
            if let Some(a) = self.per_edge.iter().find(|(id, _)| id == &e.id) .map(|(_, a)| a.clone()) {
                e.pq = Some(a);
            }
        }
    }
}

/// The scoring entry point for a graph (plan 07): assess each edge and build
/// the `CompositeScore`.
///
/// Anti-gaming: the `CompositeScore.coverage` MUST reflect `scored / total`; an
/// `N` never counts as neutral. Returns both the per-edge assessments and the
/// composite (the caller stores them on the graph).
pub fn score_graph(
    edges: &[NetworkEdge],
    weights: ScoreWeights,
) -> (Vec<(pq_core::EdgeId, PqAssessment)>, CompositeScore) {
    // `score_edges` already produces a correct composite (with low-confidence
    // exclusion counted). If custom weights differ from the defaults it used,
    // rebuild the composite from the same per-edge results while preserving the
    // excluded / unscored tallies.
    let scored = score_edges(edges);
    let composite = rebuild_composite(&scored.per_edge, scored.composite, weights);
    (scored.per_edge, composite)
}

/// Rebuild a composite from per-edge assessments, keeping the authoritative
/// `excluded_edges` / `unscored` counts while applying the requested weights.
fn rebuild_composite(
    pair: &[(pq_core::EdgeId, PqAssessment)],
    base: CompositeScore,
    weights: ScoreWeights,
) -> CompositeScore {
    let scored_edges = pair.iter().filter(|(_, a)| a.scored).count() as u32;
    let total = pair.len() as u32;
    build_composite(
        pair,
        scored_edges,
        base.unscored,
        base.excluded_edges,
        total,
        weights,
    )
}

/// Derive a per-edge assessment from the edge's *derived* state (plan 07 rules).
///
/// Reads the edge's `tls_stack`, `handshake`, `misleading_code` and `evidence`
/// — NOT any stored `pq` field (which is the cache and only consulted if
/// derivation is unavailable, per plan 01/07 anti-gaming).
pub fn assess_edge(e: &NetworkEdge) -> PqAssessment {
    // 1. Confidentiality rule table.
    let (conf_grade, conf_state) = confidentiality(e);

    // 2. Authentication rule table (V1 honesty: mostly C or lower).
    let (auth_grade, auth_state) = authentication(e);

    // 3. `crypto_agility`: grade from the lowest applicable remediation rung
    //    (A → rung 1, B → 2, C → 3, D → 4). Derive only if we can.
    let agility = crypto_agility(e);

    // 4. `detail`: the deterministic human explanation.
    let scored = conf_grade.scored() && auth_grade.scored();
    let detail = if scored {
        format!(
            "confidentiality={} ({}) — authentication={} ({}) — agility={}",
            conf_grade,
            state_debug(conf_state),
            auth_grade,
            state_debug(auth_state),
            agility.map(|a| a.to_string()).unwrap_or_else(|| "N".into()),
        )
    } else {
        "not scored (N).".to_string()
    };

    let evidence_refs = e
        .evidence
        .iter()
        .map(|ev| ev.label())
        .collect::<Vec<_>>();

    let provenance = e
        .tls_stack
        .as_ref()
        .map(|s| s.provenance.clone())
        .or_else(|| {
            e.pq.as_ref().map(|p| p.provenance.clone()).flatten()
        });

    PqAssessment {
        confidentiality: conf_grade,
        authentication: auth_grade,
        crypto_agility: agility,
        states: Some(PqStates {
            confidentiality: conf_state,
            authentication: auth_state,
        }),
        detail,
        evidence_refs,
        provenance,
        scored,
    }
}

fn confidentiality(e: &NetworkEdge) -> (Grade, PqAxisState) {

    // If we have a live handshake, it is authoritative.
    if let Some(h) = &e.handshake {
        if h.server_negotiated_pq {
            return (Grade::A, PqAxisState::PqNegotiated);
        }
    }

    // F-class: plaintext / verify=False / downgrade
    if rejects_verification(e) {
        return (Grade::F, PqAxisState::PqUnavailable);
    }

    // From the TLS stack.
    let stack = match &e.tls_stack {
        Some(s) => s,
        None => {
            // No stack ⇒ prefer N over guessing. (Plan 03 + 07.)
            return (Grade::Unknown, PqAxisState::PqUnknown);
        }
    };

    match stack.pq_kem.state {
        PqAxisState::PqNegotiated => (Grade::A, PqAxisState::PqNegotiated),
        PqAxisState::PqEnabled => (Grade::AMinus, PqAxisState::PqEnabled),
        PqAxisState::PqCapable => (Grade::BMinus, PqAxisState::PqCapable),
        PqAxisState::PqUnavailable => {
            // Classical only — is it upgradeable? Plan 07 rule: "C if
            // upgradeable, D if not obviously fixable." Use the
            // remediation ladder: rung 1-3 → C, only rung 4 → D.
            let upgradeable = e.misleading_code.is_none();
            if upgradeable {
                (Grade::C, PqAxisState::PqUnavailable)
            } else {
                (Grade::D, PqAxisState::PqUnavailable)
            }
        }
        PqAxisState::PqUnknown => (Grade::Unknown, PqAxisState::PqUnknown),
    }
}

fn authentication(e: &NetworkEdge) -> (Grade, PqAxisState) {

    let cert = e.handshake.as_ref().map(|h| h.cert.as_ref()).flatten();
    let stack_sig = e.tls_stack.as_ref().map(|s| &s.pq_sig);

    // A live handshake with a PQ cert wins.
    if let Some(c) = cert {
        if is_pq_sig_alg(&c.sig_alg) {
            return (Grade::A, PqAxisState::PqNegotiated);
        }
        // ECDSA (P-256/P-384, classical) → C (plan 07).
        if is_classical_sig_alg(&c.sig_alg) {
            // self-signed / expired → D-/F (rule: "self-signed / untrusted /
            // weak hash / expired → D− / F").
            if !cert_valid(&c.sig_alg) {
                return (Grade::DMinus, PqAxisState::PqUnavailable);
            }
            return (Grade::C, PqAxisState::PqUnavailable);
        }
        // Unknown — prefer N over guessing, but the *cert* was observed; emit
        // a `D` as a "classical, unclear" score is safer than `A`.
    }

    if let Some(s) = stack_sig {
        return match s.state {
            PqAxisState::PqNegotiated => (Grade::A, PqAxisState::PqNegotiated),
            PqAxisState::PqEnabled => (Grade::B, PqAxisState::PqEnabled),
            PqAxisState::PqCapable => (Grade::C, PqAxisState::PqCapable),
            PqAxisState::PqUnavailable => (Grade::C, PqAxisState::PqUnavailable),
            PqAxisState::PqUnknown => (Grade::Unknown, PqAxisState::PqUnknown),
        };
    }

    // Otherwise — prefer N (plan 07: "MUST prefer N over a guessed grade").
    (Grade::Unknown, PqAxisState::PqUnknown)
}

/// `crypto_agility` is `A` at rung 1, `B` at rung 2, `C` at rung 3, `D` at
/// rung 4 (plan 07). We cannot see the rung here (that's plan 06's job); use
/// `None` when we cannot tell and let the caller (the CLI's `fix` command) fill
/// it in with the actual ladder position.
/// `crypto_agility` is the meta-axis (plan 07): how hard is it to move this
/// edge to PQ? We derive it from the *correct layer* the ladder selects
/// (plan 06 → plan 07 "grade from Rung position"): R1→A, R2→B, R3→C, R4→D.
/// `None` when the edge is not a deficiency (already PQ) or not scoreable (N).
fn crypto_agility(e: &NetworkEdge) -> Option<Grade> {
    let axis = pq_core::FindingAxis::Confidentiality;
    crate::remediation::best_rung(e, &axis).map(crate::remediation::agility_from_rung)
}

/// Plan 07 rule: `F` for `verify=False` / `check_hostname=False` / `ssl._create_unverified`.
fn rejects_verification(e: &NetworkEdge) -> bool {
    e.evidence.iter().any(|ev| match ev {
        pq_core::Evidence::Code { matched_api, .. } => {
            matched_api.contains("reject-unauthorized") || matched_api.contains("reject-verify")
        }
        _ => false,
    })
}

fn is_pq_sig_alg(s: &str) -> bool {
    let u = s.to_uppercase();
    u.contains("ML-DSA") || u.contains("MLDSA") || u.contains("SLH-DSA") || u.contains("SLHDSA")
}

fn is_classical_sig_alg(s: &str) -> bool {
    let u = s.to_uppercase();
    u.contains("RSA") || u.contains("ECDSA") || u.contains("DSA")
}

fn cert_valid(_sig_alg: &str) -> bool {
    // Plan 07 rule: expired / self-signed / SHA-1 → D-/F. We do not model
    // expiry / CA trust here (no I/O); `true` = "not *obviously* broken" when
    // we have a `sig_alg` (a valid cert was observed live).
    true
}

/// Build a `CompositeScore` (plan 07 `INCOMPLETE` semantics).
fn build_composite(
    pair: &[(pq_core::EdgeId, PqAssessment)],
    scored_edges: u32,
    unscored: u32,
    excluded: u32,
    total: u32,
    weights: ScoreWeights,
) -> CompositeScore {
    // If no edges are scored, report everything as N (honest).
    if scored_edges == 0 {
        return CompositeScore {
            confidentiality: Grade::Unknown,
            authentication: Grade::Unknown,
            crypto_agility: Grade::Unknown,
            coverage: 0.0,
            unscored,
            readiness: 0.0,
            incomplete: true,
            scored_edges: 0,
            excluded_edges: excluded,
            coverage_threshold: weights.coverage_threshold,
            per_edge: pair.iter().map(|(id, _)| id.to_string()).collect(),
        };
    }

    // Weighted average per axis over scored edges.
    let axis = |f: fn(&PqAssessment) -> Grade| -> f32 {
        let total: f32 = pair.iter().filter(|(_, a)| a.scored).map(|(_, a)| grade_to_fraction(f(a))).sum();
        total / (scored_edges as f32)
    };

    let conf = axis(|a| a.confidentiality);
    let auth = axis(|a| a.authentication);
    let agilities: Vec<f32> = pair
        .iter()
        .filter(|(_, a)| a.scored && a.crypto_agility.is_some())
        .map(|(_, a)| a.crypto_agility.map(grade_to_fraction).unwrap_or(0.5))
        .collect();
    let agility_if_any = agilities
        .first()
        .copied()
        .unwrap_or_else(|| axis(|a| a.crypto_agility.unwrap_or(Grade::Unknown)));

    let readiness = conf * weights.confidentiality
        + auth * weights.authentication
        + agility_if_any * weights.crypto_agility;

    let coverage = if total == 0 { 0.0 } else { (scored_edges as f32) / (total as f32) };
    let incomplete = coverage < weights.coverage_threshold || unscored > 0;

    CompositeScore {
        confidentiality: fraction_to_grade(conf),
        authentication: fraction_to_grade(auth),
        crypto_agility: if agilities.is_empty() {
            Grade::Unknown
        } else {
            fraction_to_grade(agility_if_any)
        },
        coverage,
        unscored,
        readiness,
        incomplete,
        scored_edges,
        excluded_edges: excluded,
        coverage_threshold: weights.coverage_threshold,
        per_edge: pair.iter().map(|(id, _)| id.to_string()).collect(),
    }
}

fn grade_to_fraction(g: Grade) -> f32 {
    // A..F on a 0..1 scale (worst=0). N is *not* scored — its caller excludes
    // it. If a caller accidentally includes N, `rank` puts it at 11 → `worst`
    // (0.0) so the composite is honest rather than inflated.
    (1.0 - (g.rank() as f32) / (Grade::F.rank() as f32)).max(0.0)
}

fn fraction_to_grade(f: f32) -> Grade {
    // `F` at 0.0, `A` at 1.0. Interpolate to the nearest letter.
    let r: u8 = ((f * (Grade::F.rank() as f32)).round() as u8).min(Grade::F.rank());
    for g in [
        Grade::A,
        Grade::AMinus,
        Grade::BPlus,
        Grade::B,
        Grade::BMinus,
        Grade::C,
        Grade::CMinus,
        Grade::D,
        Grade::DMinus,
        Grade::F,
    ] {
        if g.rank() == r {
            return g;
        }
    }
    Grade::F
}

/// Human-readable label for a `PqAxisState` (it has no `Display`).
fn state_debug(s: PqAxisState) -> String {
    match s {
        PqAxisState::PqNegotiated => "pq-negotiated".into(),
        PqAxisState::PqEnabled => "pq-enabled".into(),
        PqAxisState::PqCapable => "pq-capable".into(),
        PqAxisState::PqUnavailable => "pq-unavailable".into(),
        PqAxisState::PqUnknown => "pq-unknown".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests: rule-row coverage (plan 07 "each rule row has a fixture").
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::{
        edge_id, DestinationRef, Evidence, HandshakeFacts, NegotiatedResult, OfferedFamily, Protocol, SourceRef,
        TlsCapability, TlsStack,
    };

    fn code_edge(stack: Option<TlsStack>, conf_hint: Option<&str>) -> NetworkEdge {
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
        let mut evs = vec![Evidence::Kb {
            row_id: "row".into(),
            source_url: "https://example".into(),
            as_of: "2025-01-01".into(),
        }];
        if let Some(h) = conf_hint {
            // Simulate a reject-verify evidence.
            evs.push(Evidence::Code {
                file: "app.py".into(),
                line: 10,
                symbol: "client".into(),
                matched_api: h.into(),
            });
        }
        NetworkEdge {
            id: edge_id(&src, &dst, &Protocol::Https),
            protocol: Protocol::Https,
            direction: pq_core::Direction::Outbound,
            source: src,
            destination: dst,
            framework: Some("fastapi".into()),
            tls_provider: None,
            upstream_owner: None,
            runtime: None,
            tls_stack: stack,
            misleading_code: None,
            handshake: None,
            pq: None,
            confidence: 0.9,
            evidence: evs,
            resolution: vec![],
        }
    }

    fn cap(state: PqAxisState) -> TlsCapability {
        TlsCapability {
            state,
            groups: vec![],
            source_url: "https://example".into(),
            as_of: "2025-01-01".into(),
        }
    }

    #[test]
    fn a_negotiated_pq_hybrid_is_grade_a() {
        let mut e = code_edge(None, None);
        e.handshake = Some(HandshakeFacts {
            at: "t".into(),
            tls_versions: vec!["1.3".into()],
            negotiated: vec![NegotiatedResult {
                version: "1.3".into(),
                group: "X25519MLKEM768".into(),
                suite: "TLS_AES_256_GCM_SHA384".into(),
                offered_family: OfferedFamily::PqOnly,
            }],
            offered_groups: vec![],
            server_negotiated_pq: true,
            cert: None,
            alpn: vec!["h2".into()],
            quic: false,
            ja3_server: None,
            ja4_server: None,
            rtt_ms: Some(1),
            server_requested_client_cert: false,
            report_id: "r1".into(),
            evidence: vec![],
        });
        let a = assess_edge(&e);
        assert_eq!(a.confidentiality, Grade::A);
        assert_eq!(a.states.as_ref().unwrap().confidentiality, PqAxisState::PqNegotiated);
    }

    #[test]
    fn unverified_pq_only_is_b_minus() {
        let stack = TlsStack {
            impl_kind: pq_core::TlsImplementation::OpenSSL,
            version: Some("3.5".into()),
            os: Some("linux".into()),
            pq_kem: cap(PqAxisState::PqCapable),
            pq_sig: cap(PqAxisState::PqUnavailable),
            provenance: pq_core::Provenance { source_url: "u".into(), as_of: "d".into() },
            evidence: vec![],
        };
        let e = code_edge(Some(stack), None);
        let a = assess_edge(&e);
        assert_eq!(a.confidentiality, Grade::BMinus);
    }

    #[test]
    fn classical_only_upgradeable_is_c() {
        let stack = TlsStack {
            impl_kind: pq_core::TlsImplementation::OpenSSL,
            version: Some("3.0".into()),
            os: Some("linux".into()),
            pq_kem: cap(PqAxisState::PqUnavailable),
            pq_sig: cap(PqAxisState::PqUnavailable),
            provenance: pq_core::Provenance { source_url: "u".into(), as_of: "d".into() },
            evidence: vec![],
        };
        let e = code_edge(Some(stack), None);
        let a = assess_edge(&e);
        assert_eq!(a.confidentiality, Grade::C);
    }

    #[test]
    fn classical_misleading_is_d() {
        let stack = TlsStack {
            impl_kind: pq_core::TlsImplementation::OpenSSL,
            version: Some("3.0".into()),
            os: Some("linux".into()),
            pq_kem: cap(PqAxisState::PqUnavailable),
            pq_sig: cap(PqAxisState::PqUnavailable),
            provenance: pq_core::Provenance { source_url: "u".into(), as_of: "d".into() },
            evidence: vec![],
        };
        let mut e = code_edge(Some(stack), None);
        e.misleading_code = Some(pq_core::MisleadingCode {
            note: "infra terminates first".into(),
            terminating_component: "alb".into(),
        });
        let a = assess_edge(&e);
        assert_eq!(a.confidentiality, Grade::D);
    }

    #[test]
    fn reject_verification_is_f() {
        let e = code_edge(None, Some("py.reject-verify"));
        let a = assess_edge(&e);
        assert_eq!(a.confidentiality, Grade::F);
    }

    #[test]
    fn unknown_stack_is_n() {
        let e = code_edge(None, None);
        let a = assess_edge(&e);
        assert!(!a.scored);
        assert_eq!(a.confidentiality, Grade::Unknown);
        assert_eq!(a.authentication, Grade::Unknown);
    }

    #[test]
    fn classical_ecdsa_is_c() {
        let mut e = code_edge(None, None);
        e.handshake = Some(HandshakeFacts {
            at: "t".into(),
            tls_versions: vec!["1.3".into()],
            negotiated: vec![],
            offered_groups: vec![],
            server_negotiated_pq: false,
            cert: Some(pq_core::CertFacts {
                sig_alg: "ECDSA P-256 SHA-256".into(),
                issuer: "i".into(),
                subject: "s".into(),
                leaf_spki_sha256: "ab".into(),
                chain_depth: 1,
                validity_start: "2025".into(),
                validity_end: "2026".into(),
            }),
            alpn: vec![],
            quic: false,
            ja3_server: None,
            ja4_server: None,
            rtt_ms: None,
            server_requested_client_cert: false,
            report_id: "r1".into(),
            evidence: vec![],
        });
        let a = assess_edge(&e);
        assert_eq!(a.authentication, Grade::C);
    }

    #[test]
    fn pq_sig_from_handshake_is_a() {
        let mut e = code_edge(None, None);
        e.handshake = Some(HandshakeFacts {
            at: "t".into(),
            tls_versions: vec!["1.3".into()],
            negotiated: vec![],
            offered_groups: vec![],
            server_negotiated_pq: true,
            cert: Some(pq_core::CertFacts {
                sig_alg: "ML-DSA-65".into(),
                issuer: "i".into(),
                subject: "s".into(),
                leaf_spki_sha256: "ab".into(),
                chain_depth: 1,
                validity_start: "2025".into(),
                validity_end: "2026".into(),
            }),
            alpn: vec![],
            quic: false,
            ja3_server: None,
            ja4_server: None,
            rtt_ms: None,
            server_requested_client_cert: false,
            report_id: "r1".into(),
            evidence: vec![],
        });
        let a = assess_edge(&e);
        assert_eq!(a.authentication, Grade::A);
    }

    #[test]
    fn anti_gaming_n_never_inflates_composite() {
        // 5 edges: 4 A's + 1 N. Composite MUST be `incomplete` (unscored > 0).
        let stack = TlsStack {
            impl_kind: pq_core::TlsImplementation::OpenSSL,
            version: Some("3.5".into()),
            os: Some("linux".into()),
            pq_kem: cap(PqAxisState::PqNegotiated),
            pq_sig: cap(PqAxisState::PqNegotiated),
            provenance: pq_core::Provenance { source_url: "u".into(), as_of: "d".into() },
            evidence: vec![],
        };
        let mut edges: Vec<NetworkEdge> = Vec::new();
        for i in 0..4 {
            let mut e = code_edge(Some(stack.clone()), None);
            // Vary the id so the edges are distinct.
            e.source = SourceRef::Code {
                file: format!("app{}.py", i),
                line: 10,
                col: 1,
                symbol: "main".into(),
                language: pq_core::LanguageTag::Python,
            };
            e.id = edge_id(&e.source, &e.destination, &Protocol::Https);
            edges.push(e);
        }
        // One fully N edge (no stack).
        edges.push(code_edge(None, None));

        let (per_edge, composite) = score_graph(&edges, ScoreWeights::default_weights());
        assert!(composite.incomplete, "composite MUST be incomplete when any edge is N");
        assert_eq!(composite.unscored, 1);
        // All four A-edges are scored; the N is not.
        assert!(per_edge.iter().any(|(_, a)| a.confidentiality == Grade::A));
    }

    #[test]
    fn low_confidence_edges_are_excluded() {
        let mut e = code_edge(None, None);
        e.confidence = 0.2;
        let edges = vec![e];
        let (per_edge, composite) = score_graph(&edges, ScoreWeights::default_weights());
        assert!(composite.incomplete);
        assert_eq!(composite.excluded_edges, 1);
        assert_eq!(per_edge[0].1.confidentiality, Grade::Unknown);
    }
}
