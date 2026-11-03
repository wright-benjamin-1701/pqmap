//! `pqmap` — PQC migration control plane (V1 CLI).
//!
//! Commands (plan 08):
//!
//! - `pqmap scan <path>` — build the `EndpointGraph` (source + IaC + KB).
//! - `pqmap score [--graph g.json]` — re-score a stored graph (anti-gaming).
//! - `pqmap fix [--dry-run]` — emit the plan-06 remediation ladder.
//! - `pqmap probe --graph g.json [--allow-hosts …]` — live-verify (plan 04).
//! - `pqmap explain <edge-id>` — `--explain` chain (plan 02).
//!
//! Determinism (plan 08 #7): `--no-timestamp` omits `scanned_at`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use pq_analyzers::platform::{infer_from_files as platform_infer_files};
use pq_analyzers::{AnalysisContext, Catalog, IaCDetector, ScanOptions};
use pq_core::{
    CompositeScore, EdgeId, EndpointGraph, FindingAxis, NetworkEdge, RemediationPlan,
    SarifDocument,
};
use pq_probe::{probe_target, HostAllowlist, ProbeOptions, Target};
use pq_scoring::engine::score_edges;
use pq_scoring::remediation::{evaluate, LadderInput};

#[derive(Parser)]
#[command(author = "pqmap", version, about = "PQC migration control plane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the EndpointGraph from source + IaC + KB.
    Scan {
        path: PathBuf,
        #[arg(long, default_value = "pqmap.graph.json")]
        out: PathBuf,
        #[arg(long)]
        no_timestamp: bool,
        #[arg(long)]
        sarif: Option<PathBuf>,
        #[arg(long)]
        cbom: Option<PathBuf>,
    },
    /// Re-score a stored graph.
    Score {
        #[arg(long, default_value = "pqmap.graph.json")]
        graph: PathBuf,
        #[arg(long)]
        write: bool,
    },
    /// Emit the plan-06 remediation ladder.
    Fix {
        #[arg(long, default_value = "pqmap.graph.json")]
        graph: PathBuf,
        #[arg(long)]
        dry_run: bool,
    },
    /// Live-verify a stored graph's destinations.
    Probe {
        #[arg(long, default_value = "pqmap.graph.json")]
        graph: PathBuf,
        #[arg(long)]
        allow_hosts: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        explain_edge: Option<EdgeId>,
        #[arg(long)]
        write: bool,
    },
    /// Chain `--explain` chain for a specific edge.
    Explain {
        edge_id: EdgeId,
        #[arg(long, default_value = "pqmap.graph.json")]
        graph: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pqmap: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan {
            path,
            out,
            no_timestamp,
            sarif,
            cbom,
        } => scan(&path, &out, no_timestamp, sarif, cbom),
        Cmd::Score { graph, write } => score(&graph, write),
        Cmd::Fix { graph, dry_run } => fix(&graph, dry_run),
        Cmd::Probe {
            graph,
            allow_hosts,
            dry_run,
            explain_edge,
            write,
        } => probe(&graph, allow_hosts, dry_run, explain_edge, write),
        Cmd::Explain { edge_id, graph } => explain(&edge_id, &graph),
    }
}

fn scan(
    root: &Path,
    out: &Path,
    no_timestamp: bool,
    sarif: Option<PathBuf>,
    cbom: Option<PathBuf>,
) -> Result<()> {
    anyhow::ensure!(root.is_dir(), "not a directory: {}", root.display());

    let catalog = Catalog::built_in().unwrap();
    let opts = ScanOptions {
        max_files: 5_000,
        path_filter: None,
        skip_tests: true,
    };

    // Single unified walk replaces 4 independent tree walks.
    let repo_files = pq_analyzers::walk::collect(
        root,
        opts.max_files,
        opts.skip_tests,
        opts.path_filter.as_deref(),
    );

    let mut det = IaCDetector::new();
    det.run_on_files(root, &repo_files.config);
    let infra = det.into_components();

    let ctx = &AnalysisContext {
        repo_root: root.to_path_buf(),
        catalog: &catalog,
        options: &opts,
        infra: &infra,
    };
    let (nodes, mut edges) = pq_analyzers::pipeline::run(ctx, &repo_files.source);

    // Plan 03: platform inference — resolve the Docker base (runtime, version,
    // OS) once, and attach it to every edge as `RuntimeFacts` + a matching
    // `TlsStack` (the resolver looks up the matching KB row by
    // `(runtime, version, os)`). A Python/Node/Net runtime without a base
    // image resolves to `pq-unknown` (plan 03: degrade, don't guess).
    let platform = platform_infer_files(root, &repo_files.docker, &repo_files.ci, &repo_files.config);
    let os = platform.os.map(|o| o.as_str().to_string()).unwrap_or_else(|| "unknown".to_string());
    let platform_evid: Vec<pq_core::Evidence> = platform.docker_bases.iter().map(|d| {
        pq_core::Evidence::Config {
            file: d.file.clone(),
            snippet: format!("FROM {}", d.image),
            line: d.line,
        }
    }).collect();

    let resolver = pq_kb::Resolver::new();
    let mut tls_cache: std::collections::HashMap<(String, Option<String>, String), pq_core::TlsStack> =
        std::collections::HashMap::new();
    for e in edges.iter_mut() {
        // Prefer the Docker base's runtime / version when it matches the
        // edge's language; otherwise fall back to the language heuristic.
        let lang_runtime = edge_runtime_from_language(e);
        let (name, ver) = if let Some(b) = platform.docker_bases.iter().find(|b| b.runtime.as_deref() == Some(lang_runtime.as_str())) {
            (b.runtime.clone().unwrap_or(lang_runtime.clone()), b.version.clone())
        } else {
            (lang_runtime, None)
        };
        let tfm = match name.as_str() {
            "python" | "node" | "dotnet" => Some(format!("{} {}", name, ver.as_deref().unwrap_or("unknown"))),
            _ => None,
        };
        e.runtime = Some(pq_core::RuntimeFacts {
            tfm,
            os: Some(os.clone()),
            name: Some(name.clone()),
            version: ver.clone(),
            node_openssl: None,
            evidence: platform_evid.clone(),
        });
        let cache_key = (name.clone(), ver.clone(), os.clone());
        let stack = tls_cache
            .entry(cache_key)
            .or_insert_with(|| resolver.resolve(&name, ver.as_deref(), &os))
            .clone();
        e.tls_stack = Some(stack);
    }

    // PQ config detection: scan source files for PQ-enabling patterns and
    // upgrade edges from PqCapable → PqEnabled where evidence is found.
    let pq_evidence = pq_analyzers::detect_pq_config_from_files(root, &repo_files.source);
    pq_analyzers::upgrade_pq_enabled(&mut edges, &pq_evidence, &infra);

    // Re-apply plan 05 topology for edges whose `tls_provider` is infra:
    // the `misleading_code` finding flags code that looks like it owns TLS but
    // an upstream component (ALB / nginx / …) terminates TLS first.
    for e in edges.iter_mut() {
        if let pq_core::TlsOwner::Infra { component } = e.tls_provider.clone().unwrap_or(
            pq_core::TlsOwner::Unknown,
        ) {
            if e.misleading_code.is_none() {
                e.upstream_owner = Some(pq_core::TlsOwner::Library {
                    name: e
                        .framework
                        .clone()
                        .unwrap_or_else(|| "code".into()),
                    version: None,
                });
                e.misleading_code = Some(pq_core::MisleadingCode {
                    note: format!(
                        "{component} terminates TLS before the application code — \
                         a code-level PQ change has no effect"
                    ),
                    terminating_component: component.clone(),
                });
            }
        }
    }

    // Plan 07: score each edge and apply the derived grades onto the edges.
    let scored = score_edges(&edges);
    let composite = scored.composite.clone();
    scored.apply(&mut edges);
    let kb_rows_used = collect_kb_rows_used(&edges);

    let g = EndpointGraph {
        schema: 1,
        nodes,
        edges,
        input_hash: None,
        kb_rows_used,
        score: Some(composite.clone()),
        scanned_at: if no_timestamp { None } else { Some(iso_now()) },
    };

    let json = serde_json::to_string_pretty(&g)?;
    fs::write(out, json.as_bytes()).with_context(|| format!("write {}", out.display()))?;

    let sarif_path = sarif.unwrap_or_else(|| {
        let s = out.to_string_lossy().to_string();
        let base = s.strip_suffix(".json").unwrap_or(&s);
        std::path::PathBuf::from(format!("{base}.sarif.json"))
    });
    let doc = SarifDocument::from_edges(&g.edges);
    fs::write(&sarif_path, serde_json::to_string_pretty(&doc)?)
        .with_context(|| format!("write SARIF {}", sarif_path.display()))?;

    if let Some(p) = cbom {
        let v = cbom_json(&g.edges);
        fs::write(&p, serde_json::to_string_pretty(&v)?)
            .with_context(|| format!("write CBOM {}", p.display()))?;
    }

    print_composite(&composite);
    println!(
        "\n{} edges | {} nodes → {}",
        g.edges.len(),
        g.nodes.len(),
        out.display()
    );
    Ok(())
}

/// Map an edge's source language to a KB runtime moniker (plan 03).
/// Used when the edge's language does not match the Docker base.
fn edge_runtime_from_language(e: &NetworkEdge) -> String {
    match &e.source {
        pq_core::SourceRef::Code { language, .. } => match language {
            pq_core::LanguageTag::Js | pq_core::LanguageTag::Ts => "node".to_string(),
            pq_core::LanguageTag::Csharp => "dotnet".to_string(),
            pq_core::LanguageTag::Python => "python".to_string(),
            pq_core::LanguageTag::Java => "jvm".to_string(),
            pq_core::LanguageTag::Go => "go".to_string(),
            pq_core::LanguageTag::Rust => "openssl".to_string(),
            _ => "openssl".to_string(),
        },
        _ => "openssl".to_string(),
    }
}

fn print_composite(c: &CompositeScore) {
    println!(
        "Quantum Security{}  Confidentiality={}  Authentication={}  Crypto-Agility={}  \
         Coverage={:.0}%  N-unscored={}  Edges={}/{}  Readiness={:.2}",
        if c.incomplete { "  [INCOMPLETE]" } else { "" },
        c.confidentiality,
        c.authentication,
        c.crypto_agility,
        c.coverage * 100.0,
        c.unscored,
        c.scored_edges,
        c.scored_edges + c.unscored + c.excluded_edges,
        c.readiness,
    );
}

fn collect_kb_rows_used(edges: &[NetworkEdge]) -> Vec<pq_core::KbRowUsed> {
    let mut map: std::collections::BTreeMap<String, pq_core::KbRowUsed> =
        std::collections::BTreeMap::new();
    for e in edges {
        for ev in &e.evidence {
            if let pq_core::Evidence::Kb { row_id, source_url, as_of } = ev {
                map.entry(row_id.clone()).or_insert_with(|| pq_core::KbRowUsed {
                    row_id: row_id.clone(),
                    source_url: source_url.clone(),
                    as_of: as_of.clone(),
                    used_for: vec![],
                }).used_for.push(e.id.0.to_string());
            }
        }
    }
    map.into_values().collect()
}

fn score(graph: &Path, write: bool) -> Result<()> {
    let mut g = load_graph(graph)?;
    let (per, comp) = pq_scoring::score_graph(&g.edges, pq_core::ScoreWeights::default_weights());
    for (id, a) in per {
        if let Some(e) = g.edges.iter_mut().find(|e| e.id == id) {
            e.pq = Some(a);
        }
    }
    g.score = Some(comp.clone());
    if write {
        fs::write(graph, serde_json::to_string_pretty(&g)?)?;
    }
    print_composite(&comp);
    Ok(())
}

fn fix(graph: &Path, _dry_run: bool) -> Result<()> {
    let g = load_graph(graph)?;
    let mut plan = RemediationPlan {
        findings: Vec::new(),
        dry_run: true,
        generated_at: Some(iso_now()),
    };
    for e in &g.edges {
        if let Some(f) = evaluate(LadderInput { edge: e, axis: FindingAxis::Confidentiality }) {
            plan.findings.push(f);
        }
    }
    plan.findings.sort_by(|a, b| a.rung.ordinal().cmp(&b.rung.ordinal()));
    print_plan(&plan);
    Ok(())
}

fn print_plan(plan: &RemediationPlan) {
    println!(
        "Remediation plan ({} findings, dry_run={}):",
        plan.findings.len(),
        plan.dry_run
    );
    if plan.findings.is_empty() {
        println!("  (no edges require remediation)");
        return;
    }
    for (i, f) in plan.findings.iter().enumerate() {
        println!(
            "  {}. edge={}  axis={}  [{}]",
            i + 1,
            f.edge_id.0,
            f.axis.label(),
            f.rung
        );
        println!("     deficiency : {}", f.deficiency);
        println!("     change     : {}", f.change);
        println!("     rationale  : {}", f.rationale);
        let ruled_out: Vec<String> =
            f.lower_rungs_ruled_out.iter().map(|r| r.rung.to_string()).collect();
        if !ruled_out.is_empty() {
            println!("     ruled-out  : {}", ruled_out.join(", "));
        }
        if f.dry_run_default {
            println!("     mode       : dry-run (proposed, not applied)");
        }
        if !f.snippets.is_empty() {
            println!(
                "     snippets   : {} action(s)",
                f.snippets.len()
            );
            for (si, s) in f.snippets.iter().enumerate() {
                println!(
                    "\n       [{}.{}] {} ({})",
                    i + 1,
                    si + 1,
                    s.title,
                    s.language
                );
                if let Some(url) = &s.doc_url {
                    println!("       docs: {url}");
                }
                println!("       ```{}", s.language);
                for line in s.code.lines() {
                    println!("       {line}");
                }
                println!("       ```");
            }
        }
    }
}

fn probe(
    graph: &Path,
    allow_hosts: Option<String>,
    dry_run: bool,
    explain_edge: Option<EdgeId>,
    write: bool,
) -> Result<()> {
    let mut g = load_graph(graph)?;

    if let Some(edge_id) = explain_edge {
        if let Some(e) = g.edges.iter().find(|e| e.id == edge_id) {
            print_explain_edge(e);
            return Ok(());
        }
        anyhow::bail!("edge {} not found in {}", edge_id.0, graph.display());
    }

    let allow = match allow_hosts {
        Some(spec) => HostAllowlist::from_spec(&spec),
        None => HostAllowlist::new(),
    };
    let mut opts = ProbeOptions::default();
    opts.allow = allow;
    opts.dry_run = dry_run;

    let mut probed = 0u32;
    let mut denied = 0u32;
    let mut failed = 0u32;
    for e in g.edges.iter_mut() {
        let (host, port, scheme) = match &e.destination {
            pq_core::DestinationRef::ResolvedTarget { host, port, scheme } => {
                (host.clone(), *port, scheme.clone())
            }
            pq_core::DestinationRef::UnresolvedExpr { .. } => continue,
        };
        let target = Target::new(host, port, scheme);
        let out = probe_target(&target, &opts);
        match (out.facts, out.zero_packets, out.error) {
            (Some(f), _, _) => {
                e.handshake = Some(f);
                probed += 1;
            }
            (None, true, Some(err)) => {
                eprintln!("  deny: {err}");
                denied += 1;
            }
            (None, false, Some(err)) => {
                eprintln!("  err : {err}");
                failed += 1;
            }
            _ => {}
        }
    }

    // Re-score after probing (plan 07 only asserts `pq-negotiated` from a live
    // observation — the engine already does this from `edge.handshake`).
    let mut re_scored = false;
    for e in g.edges.iter_mut() {
        if e.handshake.is_some() {
            e.pq = Some(pq_scoring::assess_edge(e));
            re_scored = true;
        }
    }
    if re_scored {
        let (_per, comp) =
            pq_scoring::score_graph(&g.edges, pq_core::ScoreWeights::default_weights());
        g.score = Some(comp);
    }
    if write {
        fs::write(graph, serde_json::to_string_pretty(&g)?)?;
    }
    println!(
        "probe summary: {} probed, {} denied (zero-packets), {} failed — dry_run={}",
        probed, denied, failed, dry_run
    );
    Ok(())
}

fn explain(edge_id: &EdgeId, graph: &Path) -> Result<()> {
    let g = load_graph(graph)?;
    let e = g.edges
        .iter()
        .find(|e| e.id == *edge_id)
        .ok_or_else(|| anyhow::anyhow!("edge {} not found", edge_id.0))?;
    print_explain_edge(e);
    Ok(())
}

fn print_explain_edge(e: &NetworkEdge) {
    println!(
        "edge {} — protocol={}  direction={:?}  confidence={:.2}",
        e.id.0,
        e.protocol,
        e.direction,
        e.confidence
    );
    if let pq_core::SourceRef::Code { file, line, .. } = &e.source {
        println!("  source    : {}:{line}", file);
    }
    if let Some(f) = &e.framework {
        println!("  framework : {f}");
    }
    if let Some(o) = &e.tls_provider {
        println!("  tls owner : {}", o.label());
    }
    if let Some(u) = &e.upstream_owner {
        println!("  upstream  : {}", u.label());
    }
    if let Some(r) = e.runtime.as_ref() {
        if let Some(o) = r.os.as_deref() {
            println!("  platform  : os={o}");
        }
    }
    if let Some(s) = e.tls_stack.as_ref() {
        println!(
            "  stack     : {}  pq_kem={:?}  pq_sig={:?}  as_of={}",
            s.impl_kind,
            s.pq_kem.state,
            s.pq_sig.state,
            s.provenance.as_of,
        );
    }
    for (i, st) in e.resolution.iter().enumerate() {
        println!("  [{}] {} — {} (conf={:.2})", i + 1, st.what, st.detail, st.confidence);
    }
    if let Some(mc) = &e.misleading_code {
        eprintln!(
            "  ! misleading code: {} terminates TLS first — a code-level PQ change \
             has no effect",
            mc.terminating_component
        );
    }
    if let Some(h) = &e.handshake {
        let groups: Vec<String> = h.negotiated.iter().map(|n| n.group.clone()).collect();
        println!(
            "  probe     : pq={}  groups={:?}  \
             cert={:?}",
            h.server_negotiated_pq,
            groups,
            h.cert.as_ref().map(|c| c.sig_alg.clone())
        );
    }
    if let Some(p) = &e.pq {
        println!(
            "  pq        : conf={}  auth={}  agility={:?}  scored={} — {}",
            p.confidentiality, p.authentication, p.crypto_agility, p.scored, p.detail
        );
    }
}

fn load_graph(path: &Path) -> Result<EndpointGraph> {
    let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let g: EndpointGraph = serde_json::from_str(&s)?;
    Ok(g)
}

fn cbom_json(edges: &[NetworkEdge]) -> serde_json::Value {
    let components = edges.iter().map(|e| {
        serde_json::json!({
            "bom-ref": e.id.0,
            "name": e.framework.clone().unwrap_or_else(|| format!("edge:{:?}/{:?}", e.direction, e.protocol)),
            "type": "library",
            "evidence": e.evidence.iter().map(|ev| ev.label()).collect::<Vec<_>>(),
            "pq": e.pq.as_ref().map(|p| serde_json::json!({
                "confidentiality": format!("{:?}", p.confidentiality),
                "authentication": format!("{:?}", p.authentication),
                "detail": p.detail,
            })),
        })
    }).collect::<Vec<_>>();
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    })
}

fn iso_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u64;
    let (y, m, d) = civil_day(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_day(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
