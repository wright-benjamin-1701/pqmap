//! Post-scan PQ config detection.
//!
//! Detects PQ-enabling configuration patterns in source files that upgrade
//! an edge from `PqCapable` (runtime supports PQ) to `PqEnabled` (the code
//! explicitly enables PQ negotiation). Without this pass, only a live probe
//! can reach `PqEnabled`/`PqNegotiated`.

use std::path::Path;
use std::sync::LazyLock;

use pq_core::{Evidence, LanguageTag, NetworkEdge, PqAxisState};
use rayon::prelude::*;

use crate::infra::InfraComponent;
use crate::language::Lang;

/// PQ-enabling regex patterns per language. A match means the code actively
/// enables PQ key exchange (not just that the runtime supports it).
static PQ_PATTERNS: LazyLock<Vec<(Lang, regex::Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        // C# / .NET: SslProtocols.Tls13 on a PQ-capable runtime auto-negotiates PQ
        (
            Lang::Cs,
            regex::Regex::new(r"SslProtocols\s*=\s*SslProtocols\s*\.\s*Tls13").unwrap(),
            "SslProtocols.Tls13 enables PQ negotiation on .NET 10+",
        ),
        (
            Lang::Cs,
            regex::Regex::new(r"(?i)X25519MLKEM768|MLKEM").unwrap(),
            "Explicit MLKEM group reference in .NET config",
        ),
        // Node.js / TypeScript: ecdhCurve with MLKEM group
        (
            Lang::Js,
            regex::Regex::new(r"(?i)ecdhCurve.*X25519MLKEM768|X25519MLKEM768").unwrap(),
            "Node.js TLS config with PQ hybrid group",
        ),
        (
            Lang::Ts,
            regex::Regex::new(r"(?i)ecdhCurve.*X25519MLKEM768|X25519MLKEM768").unwrap(),
            "Node.js TLS config with PQ hybrid group",
        ),
        // Python: SSLContext with MLKEM or TLS 1.3 PQ groups
        (
            Lang::Py,
            regex::Regex::new(r"(?i)X25519MLKEM768|MLKEM").unwrap(),
            "Python TLS config with PQ hybrid group",
        ),
        // Go: CurvePreferences with MLKEM or GOEXPERIMENT=mlkem
        (
            Lang::Go,
            regex::Regex::new(r"(?i)X25519MLKEM768|MLKEM|GOEXPERIMENT.*mlkem").unwrap(),
            "Go TLS config with PQ hybrid group",
        ),
        // Java: BouncyCastle JSSE PQ provider or namedGroups with MLKEM
        (
            Lang::Java,
            regex::Regex::new(r"(?i)BouncyCastleJsseProvider|namedGroups.*MLKEM|X25519MLKEM768").unwrap(),
            "Java PQ TLS provider or group configuration",
        ),
        // Rust: PQ group references in rustls / native-tls config
        (
            Lang::Rust,
            regex::Regex::new(r"(?i)X25519MLKEM768|MLKEM|post_quantum").unwrap(),
            "Rust TLS config with PQ hybrid group",
        ),
    ]
});

/// Evidence that a source file contains PQ-enabling config.
#[derive(Debug, Clone)]
pub struct PqConfigEvidence {
    pub file: String,
    pub line: u32,
    pub language: Lang,
    pub detail: String,
}

/// Scan pre-collected source files for PQ-enabling configuration patterns.
/// Uses rayon for parallel file I/O.
pub fn detect_pq_config_from_files(
    root: &Path,
    source_files: &[std::path::PathBuf],
) -> Vec<PqConfigEvidence> {
    source_files
        .par_iter()
        .filter_map(|path| {
            let lang = path
                .extension()
                .and_then(|e| Lang::from_extension(&e.to_string_lossy()))?;
            let content = std::fs::read_to_string(path).ok()?;
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned();

            let mut file_evidence = Vec::new();
            for (pat_lang, re, detail) in PQ_PATTERNS.iter() {
                if *pat_lang != lang {
                    continue;
                }
                for (i, line) in content.lines().enumerate() {
                    if re.is_match(line) {
                        file_evidence.push(PqConfigEvidence {
                            file: rel.clone(),
                            line: (i as u32) + 1,
                            language: lang,
                            detail: detail.to_string(),
                        });
                        break;
                    }
                }
            }
            if file_evidence.is_empty() {
                None
            } else {
                Some(file_evidence)
            }
        })
        .flatten()
        .collect()
}

/// Scan the source files in a repo for PQ-enabling configuration patterns.
/// Returns evidence items grouped by language.
pub fn detect_pq_config(root: &Path, max_files: usize) -> Vec<PqConfigEvidence> {
    let mut evidence = Vec::new();
    let mut files = Vec::new();
    walk_source_files(root, &mut files, max_files);

    for path in files {
        let lang = match path
            .extension()
            .and_then(|e| Lang::from_extension(&e.to_string_lossy()))
        {
            Some(l) => l,
            None => continue,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();

        for (pat_lang, re, detail) in PQ_PATTERNS.iter() {
            if *pat_lang != lang {
                continue;
            }
            for (i, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    evidence.push(PqConfigEvidence {
                        file: rel.clone(),
                        line: (i as u32) + 1,
                        language: lang,
                        detail: detail.to_string(),
                    });
                    // One match per pattern per file is enough.
                    break;
                }
            }
        }
    }
    evidence
}

/// Upgrade edges from `PqCapable` to `PqEnabled` based on PQ config evidence
/// and infra component PQ group detection.
pub fn upgrade_pq_enabled(
    edges: &mut [NetworkEdge],
    pq_evidence: &[PqConfigEvidence],
    infra: &[InfraComponent],
) {
    // Build a set of languages that have PQ config evidence.
    let pq_langs: std::collections::HashSet<LanguageTag> = pq_evidence
        .iter()
        .map(|e| core_lang(e.language))
        .collect();

    // Check if any infra component has PQ groups detected.
    let infra_has_pq = infra.iter().any(|c| c.pq_groups_detected);

    for edge in edges.iter_mut() {
        let stack = match edge.tls_stack.as_ref() {
            Some(s) => s,
            None => continue,
        };

        let edge_lang = match &edge.source {
            pq_core::SourceRef::Code { language, .. } => *language,
            _ => continue,
        };

        let edge_is_infra = is_infra_owned(edge);

        // For code-owned edges: upgrade PqCapable → PqEnabled when the code
        // has PQ config evidence.
        // For infra-owned edges: upgrade ANY state → PqEnabled when the
        // infra component has PQ groups (the app runtime's PQ state is
        // irrelevant — nginx/ALB terminates TLS, not the app).
        let code_upgrade = stack.pq_kem.state == PqAxisState::PqCapable
            && pq_langs.contains(&edge_lang);
        let infra_upgrade = infra_has_pq && edge_is_infra;

        if !code_upgrade && !infra_upgrade {
            continue;
        }

        edge.tls_stack.as_mut().unwrap().pq_kem.state = PqAxisState::PqEnabled;

        // Add config evidence to the edge.
        for ev in pq_evidence.iter().filter(|e| core_lang(e.language) == edge_lang) {
            edge.evidence.push(Evidence::Config {
                file: ev.file.clone(),
                snippet: ev.detail.clone(),
                line: ev.line,
            });
        }

        // Add infra PQ evidence if applicable.
        if infra_has_pq && edge_is_infra {
            for c in infra.iter().filter(|c| c.pq_groups_detected) {
                edge.evidence.push(Evidence::Config {
                    file: c.file.clone(),
                    snippet: "PQ groups detected in infra config (MLKEM)".to_string(),
                    line: 1,
                });
            }
        }

        edge.resolution.push(pq_core::ResolutionStep {
            what: "pq-config-detected".into(),
            detail: "PQ enablement config found in source/infra → upgraded to PqEnabled".into(),
            confidence: 0.85,
        });
    }
}

fn is_infra_owned(edge: &NetworkEdge) -> bool {
    edge.tls_provider
        .as_ref()
        .map(|o| o.is_infra())
        .unwrap_or(false)
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

fn walk_source_files(dir: &Path, out: &mut Vec<std::path::PathBuf>, max: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        if out.len() >= max {
            return;
        }
        let p = entry.path();
        if p.is_dir() {
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if matches!(
                name.as_str(),
                "node_modules" | ".git" | "target" | "vendor" | "dist" | "build" | "saas" | "fixtures"
                | ".venv" | "venv" | "__pycache__" | "obj" | "bin" | "publish" | "TestResults"
            ) {
                continue;
            }
            walk_source_files(&p, out, max);
        } else if p
            .extension()
            .and_then(|e| Lang::from_extension(&e.to_string_lossy()))
            .is_some()
        {
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_dotnet_tls13_pq_config() {
        let dir = tempfile::tempdir().unwrap();
        let cs = dir.path().join("Program.cs");
        std::fs::write(
            &cs,
            "kestrel.ConfigureHttpsDefaults(https => { https.SslProtocols = SslProtocols.Tls13; });",
        )
        .unwrap();
        let ev = detect_pq_config(dir.path(), 1000);
        assert!(!ev.is_empty(), "should detect SslProtocols.Tls13");
        assert_eq!(ev[0].language, Lang::Cs);
    }

    #[test]
    fn detects_node_mlkem_config() {
        let dir = tempfile::tempdir().unwrap();
        let js = dir.path().join("server.js");
        std::fs::write(
            &js,
            "const options = { ecdhCurve: 'X25519MLKEM768:X25519' };",
        )
        .unwrap();
        let ev = detect_pq_config(dir.path(), 1000);
        assert!(!ev.is_empty(), "should detect X25519MLKEM768 in JS");
        assert_eq!(ev[0].language, Lang::Js);
    }

    #[test]
    fn detects_go_mlkem_config() {
        let dir = tempfile::tempdir().unwrap();
        let go = dir.path().join("main.go");
        std::fs::write(
            &go,
            "cfg := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}",
        )
        .unwrap();
        let ev = detect_pq_config(dir.path(), 1000);
        assert!(!ev.is_empty(), "should detect X25519MLKEM768 in Go");
        assert_eq!(ev[0].language, Lang::Go);
    }

    #[test]
    fn detects_java_bc_pq_provider() {
        let dir = tempfile::tempdir().unwrap();
        let java = dir.path().join("App.java");
        std::fs::write(
            &java,
            "Security.addProvider(new BouncyCastleJsseProvider());",
        )
        .unwrap();
        let ev = detect_pq_config(dir.path(), 1000);
        assert!(!ev.is_empty(), "should detect BouncyCastleJsseProvider");
        assert_eq!(ev[0].language, Lang::Java);
    }

    #[test]
    fn no_pq_config_in_classical_code() {
        let dir = tempfile::tempdir().unwrap();
        let cs = dir.path().join("Startup.cs");
        std::fs::write(&cs, "builder.Services.AddHttpClient();").unwrap();
        let ev = detect_pq_config(dir.path(), 1000);
        assert!(ev.is_empty(), "classical code should not trigger PQ detection");
    }

    #[test]
    fn upgrade_pq_enabled_from_config_evidence() {
        use pq_core::*;

        let mut edge = NetworkEdge {
            id: EdgeId("test::edge".into()),
            protocol: Protocol::Https,
            direction: Direction::Outbound,
            source: SourceRef::Code {
                file: "Program.cs".into(),
                line: 10,
                col: 1,
                symbol: "HttpClient".into(),
                language: LanguageTag::Csharp,
            },
            destination: DestinationRef::UnresolvedExpr {
                expr: "test".into(),
            },
            framework: Some("system.net".into()),
            tls_provider: Some(TlsOwner::Runtime {
                name: "runtime".into(),
            }),
            upstream_owner: None,
            runtime: None,
            tls_stack: Some(TlsStack {
                impl_kind: pq_core::TlsImplementation::OpenSSL,
                version: Some("10.0".into()),
                os: Some("linux".into()),
                pq_kem: TlsCapability {
                    state: PqAxisState::PqCapable,
                    groups: vec!["X25519MLKEM768".into()],
                    source_url: String::new(),
                    as_of: String::new(),
                },
                pq_sig: TlsCapability {
                    state: PqAxisState::PqUnavailable,
                    groups: vec![],
                    source_url: String::new(),
                    as_of: String::new(),
                },
                provenance: Provenance {
                    source_url: String::new(),
                    as_of: String::new(),
                },
                evidence: vec![],
            }),
            misleading_code: None,
            handshake: None,
            pq: None,
            confidence: 0.9,
            evidence: vec![],
            resolution: vec![],
        };

        let pq_ev = vec![PqConfigEvidence {
            file: "Program.cs".into(),
            line: 28,
            language: Lang::Cs,
            detail: "SslProtocols.Tls13 enables PQ negotiation".into(),
        }];

        upgrade_pq_enabled(&mut [edge.clone()], &pq_ev, &[]);
        // Can't mutate through clone; redo properly:
        let mut edges = vec![edge];
        upgrade_pq_enabled(&mut edges, &pq_ev, &[]);
        assert_eq!(
            edges[0].tls_stack.as_ref().unwrap().pq_kem.state,
            PqAxisState::PqEnabled
        );
    }
}
