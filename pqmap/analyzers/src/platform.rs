//! Platform / OS inference (plan 03).
//!
//! TLS owner for .NET in particular forks on the OS (Schannel vs OpenSSL), so
//! the OS must be determined from evidence. Sources of OS truth, in priority
//! order (plan 03):
//!   1. IaC declaring the platform
//!   2. Dockerfile base image (e.g. `node:22-alpine`, `mcr.microsoft.com/dotnet/*`)
//!   3. CI matrix (`runs-on: ubuntu-latest` / `windows-latest`)
//!   4. `runtimeconfig.json` framework refs
//!
//! If no OS is determinable, the caller emits `os = unknown` and degrades the
//! edge's PQ capability to `pq-unknown` (plan 03: degrade, don't guess).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

/// The target operating system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Os {
    Linux,
    Windows,
    Macos,
    Unknown,
}

impl Os {
    pub fn as_str(&self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Windows => "windows",
            Os::Macos => "macos",
            Os::Unknown => "unknown",
        }
    }
}

/// A Docker base image we parsed (plan 03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DockerBase {
    pub image: String,
    pub os: Os,
    /// The runtime implied (node / dotnet / python), if recognizable.
    pub runtime: Option<String>,
    /// The runtime version (major), if in the tag.
    pub version: Option<String>,
    pub file: String,
    pub line: u32,
}

/// Aggregated platform facts for a repo.
#[derive(Clone, Debug, Default)]
pub struct PlatformFacts {
    /// The most confident OS (the first evidence found wins; plan 03 priority).
    pub os: Option<Os>,
    pub docker_bases: Vec<DockerBase>,
    pub ci_runners: BTreeSet<String>,
    /// What we found: `dockerfile` / `ci` / `runtimeconfig` / `iac` / `none`.
    pub source: String,
}

struct DockerClassifier;

/// Infer platform facts from pre-collected file lists (unified walk).
pub fn infer_from_files(
    root: &Path,
    docker_files: &[std::path::PathBuf],
    ci_files: &[std::path::PathBuf],
    config_files: &[std::path::PathBuf],
) -> PlatformFacts {
    let mut facts = PlatformFacts::default();
    let mut bases: Vec<DockerBase> = Vec::new();

    // Process Docker files
    for f in docker_files {
        if let Ok(content) = std::fs::read_to_string(f) {
            if let Ok(rel) = f.strip_prefix(root) {
                let rel = rel.to_string_lossy().into_owned();
                bases.extend(parse_dockerfile(&rel, &content));
            }
        }
    }

    // Process CI workflow files
    for f in ci_files {
        if let Ok(content) = std::fs::read_to_string(f) {
            facts.ci_runners.extend(parse_ci_runners(&content));
        }
    }

    // Process config files that may contain runs-on (non-CI YAML)
    for f in config_files {
        let name = f
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            if let Ok(content) = std::fs::read_to_string(f) {
                if content.contains("runs-on:") {
                    facts.ci_runners.extend(parse_ci_runners(&content));
                }
            }
        }
    }

    facts.docker_bases = bases;
    if let Some(first) = facts.docker_bases.first() {
        facts.os = Some(first.os);
        facts.source = "dockerfile".to_string();
    } else if !facts.ci_runners.is_empty() {
        facts.os = Some(os_from_ci(&facts.ci_runners));
        facts.source = "ci".to_string();
    } else {
        facts.os = Some(Os::Unknown);
        facts.source = "none".to_string();
    }
    facts
}

/// Infer platform facts from a repo tree (Dockerfiles, CI workflows,
/// runtimeconfig.json).
pub fn infer(root: &Path) -> PlatformFacts {
    let mut facts = PlatformFacts::default();
    let mut bases: Vec<DockerBase> = Vec::new();
    walk(root, &mut |f| {
        let name = f
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "Dockerfile"
            || name.to_lowercase().contains("dockerfile")
            || name == "docker-compose.yml"
            || name == "docker-compose.yaml"
        {
            if let Ok(content) = std::fs::read_to_string(f) {
            if let Ok(rel) = f.strip_prefix(root) {
                let rel = rel.to_string_lossy().into_owned();
                bases.extend(parse_dockerfile(&rel, &content));
            }
            }
        }
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            if let Ok(content) = std::fs::read_to_string(f) {
                if content.contains("runs-on:") || name.starts_with(".github") {
                    facts.ci_runners.extend(parse_ci_runners(&content));
                }
            }
        }
    });

    // Priority (plan 03): Dockerfile > CI > ...
    facts.docker_bases = bases;
    if let Some(first) = facts.docker_bases.first() {
        facts.os = Some(first.os);
        facts.source = "dockerfile".to_string();
    } else if !facts.ci_runners.is_empty() {
        facts.os = Some(os_from_ci(&facts.ci_runners));
        facts.source = "ci".to_string();
    } else {
        // Nothing found → unknown (plan 03: degrade to unknown).
        facts.os = Some(Os::Unknown);
        facts.source = "none".to_string();
    }
    facts
}

/// Walk a tree, calling `f` for each file (skipping vendored dirs).
fn walk(root: &Path, f: &mut dyn FnMut(&std::path::PathBuf)) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let n = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if matches!(n.as_str(), "node_modules" | ".git" | "target" | "dist" | "saas" | "fixtures" | "pqmap"
                | ".venv" | "venv" | "__pycache__" | "obj" | "bin" | "publish" | "TestResults") {
                continue;
            }
            walk(&p, f);
        } else {
            f(&p);
        }
    }
}

fn os_from_images(base: &str) -> Os {
    let b = base.to_lowercase();
    if b.contains("windows") {
        Os::Windows
    } else if b.contains("alpine") || b.contains("debian") || b.contains("ubuntu") || b.contains("bookworm") || b.contains("slim") {
        Os::Linux
    } else if b.contains("macos") || b.contains("-arm64") && b.contains("mac") {
        Os::Macos
    } else if b.starts_with("mcr.microsoft.com/dotnet/") {
        // Official .NET images default to Linux unless explicitly windows.
        Os::Linux
    } else if b.contains("public.ecr.aws/lambda/") {
        // AWS Lambda images are Linux.
        Os::Linux
    } else {
        Os::Unknown
    }
}

fn parse_dockerfile(rel: &str, content: &str) -> Vec<DockerBase> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let n = (i as u32) + 1;
        let lower = line.to_lowercase();
        if lower.trim_start().starts_with("from ") {
            let trimmed = line.trim_start();
            // Strip case-insensitive `FROM` prefix.
            let base = if trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case("from") {
                trimmed[4..].trim()
            } else {
                trimmed
            };
            let runtime = if base.contains("node") {
                Some("node".to_string())
            } else if base.contains("dotnet") || base.contains("aspnet") {
                Some("dotnet".to_string())
            } else if base.contains("python") {
                Some("python".to_string())
            } else {
                None
            };
            // `python:3.12-slim` → tag `3.12-slim` → version `3.12`
            // `dotnet/sdk:10.0` → tag `10.0` → version `10.0`
            // (major.minor, so `version_geq` against a `3.12.0` min row works).
            let version = base
                .split_once(':')
                .map(|(_, tag)| {
                    // Strip variant suffix (e.g. `-slim`, `-alpine`, ` AS builder`)
                    let tag = tag.split_whitespace().next().unwrap_or(tag);
                    tag.split('-').next().unwrap_or(tag).trim().to_string()
                })
                .filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit()));
            out.push(DockerBase {
                image: base.to_string(),
                os: os_from_images(base),
                runtime,
                version,
                file: rel.to_string(),
                line: n,
            });
        }
    }
    out
}

static CI_RUNNER_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?m)^\s*runs-on:\s*["']?([\w-]+)"#).unwrap()
});

fn parse_ci_runners(content: &str) -> Vec<String> {
    CI_RUNNER_RE
        .captures_iter(content)
        .map(|c| c[1].to_string())
        .collect()
}

fn os_from_ci(runners: &std::collections::BTreeSet<String>) -> Os {
    for r in runners {
        let r = r.to_lowercase();
        if r.contains("windows") {
            return Os::Windows;
        }
        if r.contains("macos") || r.contains("mac") {
            return Os::Macos;
        }
        if r.contains("ubuntu") || r.contains("linux") || r.contains("windows-latest") {
            if r.contains("windows") {
                return Os::Windows;
            }
            return Os::Linux;
        }
    }
    Os::Unknown
}

#[allow(dead_code)]
fn _classifier() -> DockerClassifier {
    DockerClassifier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_from_images_alpine() {
        assert_eq!(os_from_images("node:22-alpine"), Os::Linux);
    }

    #[test]
    fn os_from_images_windows() {
        assert_eq!(os_from_images("mcr.microsoft.com/windows/servercore"), Os::Windows);
    }

    #[test]
    fn os_from_images_unknown() {
        assert_eq!(os_from_images("scratch"), Os::Unknown);
    }

    #[test]
    fn os_from_images_dotnet_mcr() {
        assert_eq!(os_from_images("mcr.microsoft.com/dotnet/sdk:10.0"), Os::Linux);
        assert_eq!(os_from_images("mcr.microsoft.com/dotnet/aspnet:8.0"), Os::Linux);
    }

    #[test]
    fn os_from_images_lambda() {
        assert_eq!(os_from_images("public.ecr.aws/lambda/python:3.12"), Os::Linux);
    }

    #[test]
    fn parse_dockerfile_version_no_suffix() {
        let content = "FROM mcr.microsoft.com/dotnet/sdk:10.0\n";
        let bases = parse_dockerfile("Dockerfile", content);
        assert_eq!(bases.len(), 1);
        assert_eq!(bases[0].runtime.as_deref(), Some("dotnet"));
        assert_eq!(bases[0].version.as_deref(), Some("10.0"));
        assert_eq!(bases[0].os, Os::Linux);
    }

    #[test]
    fn parse_dockerfile_multi_stage() {
        let content = "FROM golang:1.22-alpine AS build\nRUN go build\nFROM alpine:3.19\nCOPY --from=build /app /app\n";
        let bases = parse_dockerfile("Dockerfile", content);
        assert_eq!(bases.len(), 2);
        assert_eq!(bases[0].os, Os::Linux);
        assert_eq!(bases[1].os, Os::Linux);
        assert_eq!(bases[0].version.as_deref(), Some("1.22"));
    }
}
