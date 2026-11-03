//! Integration test: Java/Spring fixture detection.

use std::path::Path;

fn scan_fixture(name: &str) -> Vec<pq_core::NetworkEdge> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut dir = Path::new(&manifest).to_path_buf();
    dir = dir.parent().unwrap().to_path_buf();
    dir.push(format!("fixtures/{name}"));

    let catalog = pq_analyzers::Catalog::built_in().unwrap();
    let opts = pq_analyzers::ScanOptions {
        max_files: 5_000,
        path_filter: None,
        skip_tests: true,
    };
    let repo_files = pq_analyzers::walk::collect(&dir, opts.max_files, opts.skip_tests, None);
    let mut det = pq_analyzers::IaCDetector::new();
    det.run_on_files(&dir, &repo_files.config);
    let infra = det.into_components();

    let ctx = &pq_analyzers::AnalysisContext {
        repo_root: dir.clone(),
        catalog: &catalog,
        options: &opts,
        infra: &infra,
    };
    let (_nodes, edges) = pq_analyzers::pipeline::run(ctx, &repo_files.source);
    edges
}

#[test]
fn java_detects_okhttp_client() {
    let edges = scan_fixture("java-spring");
    let has_okhttp = edges.iter().any(|e| {
        e.framework.as_deref() == Some("okhttp")
            && e.direction == pq_core::Direction::Outbound
    });
    assert!(has_okhttp, "expected an okhttp client edge, got: {edges:#?}");
}

#[test]
fn java_detects_spring_server() {
    let edges = scan_fixture("java-spring");
    let server = edges.iter().any(|e| {
        e.framework.as_deref() == Some("spring-boot")
            && e.direction == pq_core::Direction::Inbound
    });
    assert!(server, "expected a spring-boot server edge, got: {edges:#?}");
}
