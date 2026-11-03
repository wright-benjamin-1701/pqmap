//! The analysis pipeline (plan 02 → 05 integration).
//!
//! Per file:
//!   1. detect language by extension
//!   2. build the per-file `SymbolTable` (imports / aliases / classes / DI)
//!   3. run the line detector → `Match`es
//!   4. fold client / server matches into `NetworkEdge`s
//!   5. apply infra topology + the misleading-code finding (plan 05)
//!
//! Deterministic: same tree + lockfiles → byte-identical graph (08 #7). The
//! same scan is *re-runnable* and *composable*: runtime (03), scoring (07)
//! and probe (04) are separate passes that annotate the returned edges.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use pq_core::{
    edge_id, Direction, Evidence, GraphNode, LanguageTag, MisleadingCode, NetworkEdge,
    Protocol, SourceRef, TlsOwner,
};

use rayon::prelude::*;

use crate::catalog::{Catalog, TlsOwnerHint};
use crate::detector::{scan, Kind, Match, Reason};
use crate::infra::InfraComponent;
use crate::language::Lang;
use crate::symbol::build as build_symbol_table;

/// Options for a scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Maximum number of source files to read (guards against monorepo noise).
    pub max_files: usize,
    /// If set, only read paths under this prefix (repo-relative).
    pub path_filter: Option<String>,
    /// Skip test / mock fixture paths (plan 02 anti-FP heuristics).
    pub skip_tests: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_files: 5_000,
            path_filter: None,
            skip_tests: true,
        }
    }
}

/// Inputs shared across the scan (read once, handed to each file).
pub struct AnalysisContext<'a> {
    pub repo_root: std::path::PathBuf,
    pub catalog: &'a Catalog,
    pub options: &'a ScanOptions,
    /// Infrastructure components discovered by the IaC detector (plan 05).
    pub infra: &'a [InfraComponent],
}

/// Scans a repo and returns the graph skeleton (nodes + edges).
///
/// The returned edges have `tls_provider`, `evidence` and `resolution`
/// populated. The two-axis grades (`pq`) and the composite `score` are added
/// by the `scoring` crate (plan 07) in a later pass; the runtime `TlsStack` is
/// added by the `kb` resolver (plan 03).
pub fn run(ctx: &AnalysisContext, source_files: &[std::path::PathBuf]) -> (
    BTreeMap<String, GraphNode>,
    Vec<NetworkEdge>,
) {
    let mut nodes: BTreeMap<String, GraphNode> = BTreeMap::new();
    let mut edges: Vec<NetworkEdge> = Vec::new();

    let repo = node_name_for(ctx.repo_root.as_path());
    nodes.insert(
        "service::app".to_string(),
        GraphNode::Service {
            name: repo.clone(),
            language: None,
            file: None,
        },
    );

    // Phase 1: read + detect in parallel (each file is independent).
    let file_matches: Vec<(String, Lang, Vec<Match>)> = source_files
        .into_par_iter()
        .filter_map(|path| {
            let (rel, lang, content) = read_source(&path, &ctx.repo_root)?;
            let symbols = build_symbol_table(lang, &content);
            let matches = scan(&content, lang, ctx.catalog, &symbols);
            if matches.is_empty() {
                None
            } else {
                Some((rel, lang, matches))
            }
        })
        .collect();

    // Phase 2: fold into edges (mutates the shared `nodes` map).
    for (rel, lang, matches) in &file_matches {
        for m in matches {
            if let Some(e) = edge_for_match(ctx, &repo, rel, *lang, m, &mut nodes) {
                edges.push(e);
            }
        }
    }

    // Infra / topology pass (plan 05): set the outermost terminator + the
    // misleading-code finding where infra terminates before the app code.
    // Apply in *outermost-first* order so the highest-precedence component
    // (ALB/edge > reverse proxy > gateway) owns `tls_provider`; each less-
    // outer infra terminator is recorded as `upstream_owner`.
    let infra_sorted: Vec<&InfraComponent> = {
        let mut v: Vec<&InfraComponent> = ctx.infra.iter().filter(|c| c.terminates_tls).collect();
        v.sort_by(|a, b| b.outerness.cmp(&a.outerness).then_with(|| a.id.cmp(&b.id)));
        v
    };
    let mut edges = infra_sorted.iter().fold(edges, |acc, infra| apply_topology(acc, infra));
    edges.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    (nodes, edges)
}

fn edge_for_match(
    _ctx: &AnalysisContext,
    _repo: &str,
    rel: &str,
    lang: Lang,
    m: &Match,
    nodes: &mut BTreeMap<String, GraphNode>,
) -> Option<NetworkEdge> {
    let protocol = m
        .protocol
        .as_deref()
        .map(Protocol::from_str)
        .unwrap_or_default();

    let source = SourceRef::Code {
        file: rel.to_string(),
        line: m.line,
        col: 1,
        symbol: m.symbol.clone(),
        language: core_lang(lang),
    };

    let direction = match m.kind {
        Kind::Client => Direction::Outbound,
        Kind::Server => Direction::Inbound,
        Kind::TlsConfig | Kind::Crypto => Direction::Inbound,
    };

    let destination = match extract_destination(m) {
        Some(d) => d,
        None => pq_core::DestinationRef::UnresolvedExpr {
            expr: format!("unresolved:{}", m.api_name),
        },
    };

    // For outbound edges, ensure a destination endpoint node exists.
    if direction == Direction::Outbound {
        if let pq_core::DestinationRef::ResolvedTarget { host, .. } = &destination {
            let id = format!("endpoint::{}", host);
            if !nodes.contains_key(&id) {
                nodes.insert(
                    id,
                    GraphNode::Endpoint {
                        name: host.clone(),
                        node_kind: "external".to_string(),
                    },
                );
            }
        }
    }

    let owner = m
        .tls_owner_hint
        .map(owner_from_hint)
        .unwrap_or(TlsOwner::Unknown);

    let evidence = vec![Evidence::Code {
        file: rel.to_string(),
        line: m.line,
        symbol: m.symbol.clone(),
        matched_api: m.api_name.clone(),
    }];

    let mut resolution = vec![pq_core::ResolutionStep {
        what: "catalog-match".into(),
        detail: format!("row {} ({})", m.api_name, m.framework),
        confidence: m.confidence,
    }];
    if let Some((what, detail)) = reason_label(m.reason) {
        resolution.push(pq_core::ResolutionStep {
            what: what.into(),
            detail,
            confidence: m.confidence,
        });
    }

    // Invariant 1 (plan 01): every edge has ≥ 1 evidence item — always true
    // here. Confidence < 0.5 edges are `unverified` (still emitted, but
    // excluded from scoring by plan 07).
    Some(NetworkEdge {
        id: edge_id(&source, &destination, &protocol),
        protocol,
        direction,
        source,
        destination,
        framework: Some(m.framework.clone()),
        tls_provider: Some(owner),
        upstream_owner: None,
        runtime: None,
        tls_stack: None,
        misleading_code: None,
        handshake: None,
        pq: None,
        confidence: m.confidence,
        evidence,
        resolution,
    })
}

/// Plan 05: an external-facing code edge is re-attributed to the *outermost*
/// infrastructure terminator, the code owner is preserved as `upstream_owner`,
/// and the first-class "misleading code" finding is raised (plan 05, the
/// differentiator): code-level PQ changes have no effect when infra terminates
/// TLS first.
fn apply_topology(
    edges: Vec<NetworkEdge>,
    infra: &InfraComponent,
) -> Vec<NetworkEdge> {
    if !infra.terminates_tls {
        return edges;
    }
    edges
        .into_iter()
        .map(|mut e| {
            let code_owned = e
                .tls_provider
                .as_ref()
                .map(|o| !o.is_infra())
                .unwrap_or(false);
            if code_owned && e.misleading_code.is_none() {
                let prev = e.tls_provider.take();
                e.upstream_owner = e.upstream_owner.take().or(prev);
                e.tls_provider = Some(TlsOwner::Infra {
                    component: infra.name.clone(),
                });
                e.evidence.push(Evidence::Iac {
                    file: infra.file.clone(),
                    block: infra.kind.clone(),
                    line: infra.line,
                });
                e.misleading_code = Some(MisleadingCode {
                    note: format!(
                        "{} terminates TLS before it reaches the application code — \
                         a code-level PQ change has no effect",
                        infra.name
                    ),
                    terminating_component: infra.name.clone(),
                });
            }
            e
        })
        .collect()
}

fn owner_from_hint(h: TlsOwnerHint) -> TlsOwner {
    match h {
        TlsOwnerHint::Runtime => TlsOwner::Runtime {
            name: "runtime".into(),
        },
        TlsOwnerHint::Library => TlsOwner::Library {
            name: "library".into(),
            version: None,
        },
        TlsOwnerHint::Os => TlsOwner::Os { name: "os".into() },
        TlsOwnerHint::CodeInline => TlsOwner::CodeInline {
            impl_name: "inline".into(),
        },
        TlsOwnerHint::Infra => TlsOwner::Infra {
            component: "infra".into(),
        },
    }
}

fn reason_label(r: Reason) -> Option<(&'static str, String)> {
    match r {
        Reason::Literal => None,
        Reason::Alias => Some((
            "alias",
            "local alias bound to the client API".into(),
        )),
        Reason::Subclass => Some((
            "subclass",
            "inherited client via class hierarchy".into(),
        )),
        Reason::Di => Some((
            "di",
            "DI-registered HTTP client".into(),
        )),
        Reason::Import => Some((
            "import",
            "library imported in the file header".into(),
        )),
    }
}

fn node_name_for(root: &Path) -> String {
    root.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "app".to_string())
}

fn core_lang(l: Lang) -> LanguageTag {
    match l {
        Lang::Js => LanguageTag::Js,
        Lang::Ts => LanguageTag::Ts,
        Lang::Cs => LanguageTag::Csharp,
        Lang::Py => LanguageTag::Python,
        Lang::Java => LanguageTag::Java,
        Lang::Go => LanguageTag::Go,
        Lang::Rust => LanguageTag::Rust,
    }
}

/// Extract a resolved destination (host:port) from the match's line, if a URL
/// literal or bare hostname is present (plan 02 "destination binding, 1 hop,
/// do not guess").
///
/// Priority: a full `scheme://host[:port]` wins; if none, fall back to a bare
/// hostname containing at least one dot (a real name, not a local identifier).
/// Returns `None` when only identifiers / keywords are present (→ the caller
/// emits `UnresolvedExpr`).
static DEST_URL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)([a-z][a-z0-9+.-]*://)([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)(:\d+)?",
    ).unwrap()
});
static DEST_HOST_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"\b([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)(?::(\d+))?\b",
    ).unwrap()
});

fn extract_destination(m: &Match) -> Option<pq_core::DestinationRef> {
    let url_re = &*DEST_URL_RE;
    let host_re = &*DEST_HOST_RE;

    // Candidate strings to scan, in priority order. The raw line is most
    // faithful (the `symbol`/`api_name` may have broken URL delimiters).
    let candidates: Vec<&str> = [m.line_text.as_str(), m.symbol.as_str(), m.api_name.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();

    // 1) Full URL first (https://api.stripe.com/v1/charges).
    for text in &candidates {
        if let Some(caps) = url_re.captures(text) {
            let scheme = caps[1].trim_end_matches("://").to_string();
            let host = caps[2].to_string();
            let port = caps
                .get(3)
                .and_then(|s| s.as_str().trim_start_matches(':').parse::<u16>().ok())
                .unwrap_or(443);
            return Some(pq_core::DestinationRef::ResolvedTarget {
                host,
                port,
                scheme,
            });
        }
    }

    // 2) Bare hostname fallback (host must contain a dot and look like a real
    //    hostname, not a code identifier like `requests.get` or `java.net`).
    for text in &candidates {
        if let Some(caps) = host_re.captures(text) {
            let host = caps.get(1).map(|s| s.as_str().to_string()).unwrap_or_default();
            if host.contains('.')
                && !host.starts_with('.')
                && host.split('.').count() >= 3
                && !is_code_identifier(&host)
            {
                let port = caps
                    .get(2)
                    .and_then(|s| s.as_str().parse::<u16>().ok())
                    .unwrap_or(443);
                return Some(pq_core::DestinationRef::ResolvedTarget {
                    host,
                    port,
                    scheme: "https".to_string(),
                });
            }
        }
    }
    None
}

/// Returns true if the candidate looks like a code identifier rather than a
/// hostname (e.g. `requests.get`, `java.net`, `okhttp3.OkHttpClient`).
fn is_code_identifier(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    // Code identifiers: any segment starts with uppercase (Java class) or is a
    // known code token.
    let code_tokens = [
        "get", "post", "put", "delete", "head", "create", "run", "send",
        "request", "connect", "build", "start", "init", "new",
    ];
    parts.iter().any(|p| {
        p.chars().next().is_some_and(|c| c.is_uppercase())
            || code_tokens.contains(p)
    })
}

fn read_source(
    path: &Path,
    root: &Path,
) -> Option<(String, Lang, String)> {
    let lang = path
        .extension()
        .and_then(|e| Lang::from_extension(&e.to_string_lossy()))?;
    let content = std::fs::read_to_string(path).ok()?;
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned();
    Some((rel, lang, content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Match as DetMatch;
    use crate::detector::{Kind as DKind, Reason};

    fn make_match(line_text: &str) -> DetMatch {
        DetMatch {
            kind: DKind::Client,
            api_name: "test".into(),
            framework: "test".into(),
            line: 1,
            line_text: line_text.to_string(),
            symbol: String::new(),
            reason: Reason::Literal,
            confidence: 0.9,
            protocol: Some("https".into()),
            tls_owner_hint: None,
        }
    }

    #[test]
    fn extract_destination_full_url() {
        let m = make_match("requests.get('https://api.stripe.com/v1/charges')");
        let d = extract_destination(&m).unwrap();
        match d {
            pq_core::DestinationRef::ResolvedTarget { host, port, scheme } => {
                assert_eq!(host, "api.stripe.com");
                assert_eq!(port, 443);
                assert_eq!(scheme, "https");
            }
            _ => panic!("expected ResolvedTarget"),
        }
    }

    #[test]
    fn extract_destination_bare_host() {
        let m = make_match("connect to api.example.com");
        let d = extract_destination(&m).unwrap();
        match d {
            pq_core::DestinationRef::ResolvedTarget { host, .. } => {
                assert_eq!(host, "api.example.com");
            }
            _ => panic!("expected ResolvedTarget"),
        }
    }

    #[test]
    fn extract_destination_no_host() {
        let m = make_match("let x = 42;");
        assert!(extract_destination(&m).is_none());
    }

    #[test]
    fn core_lang_mapping_complete() {
        assert_eq!(core_lang(Lang::Js), LanguageTag::Js);
        assert_eq!(core_lang(Lang::Ts), LanguageTag::Ts);
        assert_eq!(core_lang(Lang::Cs), LanguageTag::Csharp);
        assert_eq!(core_lang(Lang::Py), LanguageTag::Python);
        assert_eq!(core_lang(Lang::Java), LanguageTag::Java);
        assert_eq!(core_lang(Lang::Go), LanguageTag::Go);
    }

    #[test]
    fn is_test_path_java_go() {
        // Test path detection moved to walk module; verify via walk::collect.
        use crate::walk;
        let dir = tempfile::tempdir().unwrap();
        let test_dir = dir.path().join("src/test/java/com/example");
        std::fs::create_dir_all(&test_dir).unwrap();
        std::fs::write(test_dir.join("FooTest.java"), "class FooTest {}").unwrap();
        let main_dir = dir.path().join("src/main/java/com/example");
        std::fs::create_dir_all(&main_dir).unwrap();
        std::fs::write(main_dir.join("Foo.java"), "class Foo {}").unwrap();
        std::fs::write(dir.path().join("handler_test.go"), "package x").unwrap();
        std::fs::write(dir.path().join("handler.go"), "package x").unwrap();
        let files = walk::collect(dir.path(), 1000, true, None);
        let names: Vec<String> = files.source.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert!(names.contains(&"Foo.java".to_string()));
        assert!(names.contains(&"handler.go".to_string()));
        assert!(!names.contains(&"FooTest.java".to_string()));
        assert!(!names.contains(&"handler_test.go".to_string()));
    }
}
