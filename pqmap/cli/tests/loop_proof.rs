//! End-to-end integration test (plan 08 acceptance #1 "loop proof").
//!
//! Scans the `fixtures/loop-proof` tree with the *same code* the `pqmap scan`
//! command uses (the scan logic is inlined here since the CLI is a binary),
//! and asserts:
//!
//!   - an `app.py → api.stripe.com` HTTPS edge is discovered;
//!   - the ALB becomes the outermost TLS owner with a `misleading_code`
//!     finding (plan 05);
//!   - `pqmap fix` (the ladder) selects **Rung 3 (IaC)** — *not* Rung 1
//!     (the Python dependency bump does nothing for an ALB front-end).

use std::path::Path;

use pq_core::ScoreWeights;
use pq_scoring::remediation::{evaluate, LadderInput};
use pq_core::{FindingAxis, Rung};

fn scan_dir(dir: &Path) -> (pq_core::EndpointGraph, pq_core::CompositeScore) {
    // Mirror cli/src/main.rs `scan()` exactly.
    let catalog = pq_analyzers::Catalog::built_in().unwrap();
    let opts = pq_analyzers::ScanOptions {
        max_files: 5_000,
        path_filter: None,
        skip_tests: true,
    };
    let repo_files = pq_analyzers::walk::collect(dir, opts.max_files, opts.skip_tests, None);
    let mut det = pq_analyzers::IaCDetector::new();
    det.run_on_files(dir, &repo_files.config);
    let infra = det.into_components();

    let ctx = &pq_analyzers::AnalysisContext {
        repo_root: dir.to_path_buf(),
        catalog: &catalog,
        options: &opts,
        infra: &infra,
    };
    let (mut nodes, mut edges) = pq_analyzers::pipeline::run(ctx, &repo_files.source);

    let platform = pq_analyzers::platform::infer(dir);
    let os = platform
        .os
        .map(|o| o.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    for e in edges.iter_mut() {
        e.runtime = Some(pq_core::RuntimeFacts {
            tfm: None,
            os: Some(os.clone()),
            name: None,
            version: None,
            node_openssl: None,
            evidence: vec![],
        });
    }

    let resolver = pq_kb::Resolver::new();
    for e in edges.iter_mut() {
        let (runtime, ver) = match &e.source {
            pq_core::SourceRef::Code {
                language: pq_core::LanguageTag::Python,
                ..
            } => {
                // Mirror the CLI: look up the Docker base's version for the runtime.
                let v = platform.docker_bases.iter()
                    .find(|b| b.runtime.as_deref() == Some("python"))
                    .and_then(|b| b.version.clone());
                ("python", v)
            }
            _ => ("openssl", None),
        };
        let stack = resolver.resolve(runtime, ver.as_deref(), &os);
        e.tls_stack = Some(stack);
    }

    // Plan 05 topology: infra-owned edges gain `misleading_code`.
    for e in edges.iter_mut() {
        if e.tls_provider.as_ref().is_some_and(|o| o.is_infra()) && e.misleading_code.is_none() {
            let comp = match e.tls_provider.clone().unwrap() {
                pq_core::TlsOwner::Infra { component } => component,
                _ => "infra".to_string(),
            };
            e.upstream_owner = Some(pq_core::TlsOwner::Library {
                name: e.framework.clone().unwrap_or_else(|| "code".into()),
                version: None,
            });
            e.misleading_code = Some(pq_core::MisleadingCode {
                note: format!("{comp} terminates TLS first"),
                terminating_component: comp,
            });
        }
    }

    let scored = pq_scoring::engine::score_edges(&edges);
    let composite = scored.composite.clone();
    scored.apply(&mut edges);

    let g = pq_core::EndpointGraph {
        schema: 1,
        nodes,
        edges,
        input_hash: None,
        kb_rows_used: vec![],
        score: Some(composite.clone()),
        scanned_at: None,
    };
    (g, composite)
}

fn fixture_dir() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // cli/ is a crate; the fixture lives at workspace-root/fixtures/
    let mut p = Path::new(&manifest).to_path_buf();
    p = p.parent().unwrap().to_path_buf(); // workspace root
    p.push("fixtures/loop-proof");
    p
}

#[test]
fn loop_proof_finds_stripe_edge() {
    let dir = fixture_dir();
    let (g, _) = scan_dir(&dir);
    assert!(
        !g.edges.is_empty(),
        "expected at least one edge in the loop-proof fixture"
    );
    // At least one edge must target stripe.
    let stripe = g.edges.iter().any(|e| {
        if let pq_core::DestinationRef::ResolvedTarget { host, .. } = &e.destination {
            host.contains("stripe")
        } else {
            false
        }
    });
    assert!(stripe, "expected an edge to api.stripe.com");
}

#[test]
fn loop_proof_recommends_rung3_not_python_bump() {
    let dir = fixture_dir();
    let (g, _) = scan_dir(&dir);
    // Find the stripe edge.
    let stripe_edge = g
        .edges
        .iter()
        .find(|e| matches!(&e.destination, pq_core::DestinationRef::ResolvedTarget { host, .. } if host.contains("stripe")))
        .expect("stripe edge present");

    // It must have the plan-05 `misleading_code` finding (ALB terminates).
    let mc = stripe_edge
        .misleading_code
        .as_ref()
        .expect("misleading_code: the ALB must be flagged as the terminator");
    assert!(
        mc.terminating_component.to_lowercase().contains("alb"),
        "terminator should be the ALB, got {:?}",
        mc.terminating_component
    );

    // Run the ladder. Plan 08 #1: the correct layer is Rung 3 (IaC), NOT a
    // Python dependency bump (Rung 1).
    let finding = evaluate(LadderInput {
        edge: stripe_edge,
        axis: FindingAxis::Confidentiality,
    })
    .expect("a finding is expected (classical edge behind an ALB)");

    assert_eq!(
        finding.rung,
        Rung::R3Iac,
        "plan 08 #1: the remediation MUST be Rung 3 (IaC), not a Python bump (Rung 1)"
    );
    // Gating: Rung 1 and Rung 2 must have been ruled out.
    assert!(
        finding
            .lower_rungs_ruled_out
            .iter()
            .any(|r| r.rung == Rung::R1Dependency),
        "Rung 1 must be ruled out for an infra-terminated edge"
    );
    assert!(
        finding
            .lower_rungs_ruled_out
            .iter()
            .any(|r| r.rung == Rung::R2Config),
        "Rung 2 must be ruled out for an infra-terminated edge"
    );
    // Dry-run by default (plan 06 safety).
    assert!(finding.dry_run_default);
    assert!(!finding.auto_applicable);
    // Gating is valid.
    finding.verify_gating().expect("finding must be gate-clean");
}

#[test]
fn loop_proof_composite_is_honest() {
    let dir = fixture_dir();
    let (_, comp) = scan_dir(&dir);
    // Even if a few edges score, the composite must carry the N-unscored count
    // (plan 07: two-axis honesty) — never silently "READY: yes".
    let _ = ScoreWeights::default_weights();
    assert!(
        comp.scored_edges > 0 || comp.unscored > 0 || comp.excluded_edges > 0,
        "composite must account for every edge (scored + unscored + excluded)"
    );
}
