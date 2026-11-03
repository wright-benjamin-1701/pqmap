//! Unified repo-tree walk (perf: single walk replaces 4 independent ones).
//!
//! `collect()` walks the tree once and classifies each file into one of four
//! buckets: `source`, `config`, `docker`, `ci`. Consumers (pipeline, IaC
//! detector, platform inference, PQ config detection) receive their subset
//! without re-walking the tree.

use std::path::{Path, PathBuf};

use crate::language::Lang;

/// Files collected from a single repo walk, classified by role.
#[derive(Debug, Default)]
pub struct RepoFiles {
    /// Source files: .js, .ts, .cs, .py, .java, .go, .rs
    pub source: Vec<PathBuf>,
    /// Config files: .conf, .json, .tf, .yml, .yaml
    pub config: Vec<PathBuf>,
    /// Docker files: Dockerfile*, docker-compose.*
    pub docker: Vec<PathBuf>,
    /// CI workflow files: .github/workflows/*.yml
    pub ci: Vec<PathBuf>,
}

const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "vendor",
    "dist",
    "build",
    "saas",
    "fixtures",
    ".venv",
    "venv",
    "__pycache__",
    "obj",
    "bin",
    "publish",
    "TestResults",
];

/// Walk the repo tree once and classify files into buckets.
///
/// - `max_source`: cap on source files (guards against monorepo noise).
/// - `skip_tests`: omit test / mock fixture paths from `source`.
/// - `path_filter`: if set, only include source files whose path contains this.
pub fn collect(
    root: &Path,
    max_source: usize,
    skip_tests: bool,
    path_filter: Option<&str>,
) -> RepoFiles {
    let mut files = RepoFiles::default();
    walk_dir(root, root, max_source, skip_tests, path_filter, &mut files);
    files
}

fn walk_dir(
    dir: &Path,
    root: &Path,
    max_source: usize,
    skip_tests: bool,
    path_filter: Option<&str>,
    out: &mut RepoFiles,
) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p
                .file_name()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default();
            if EXCLUDED_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk_dir(&p, root, max_source, skip_tests, path_filter, out);
        } else {
            classify_file(&p, root, max_source, skip_tests, path_filter, out);
        }
    }
}

fn classify_file(
    path: &Path,
    root: &Path,
    max_source: usize,
    skip_tests: bool,
    path_filter: Option<&str>,
    out: &mut RepoFiles,
) {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();

    // Docker files — use case-insensitive check without allocating.
    let name_lower_has_dockerfile = name.as_bytes().windows(10).any(|w| {
        w.eq_ignore_ascii_case(b"dockerfile")
    });
    if name == "Dockerfile"
        || name_lower_has_dockerfile
        || name == "docker-compose.yml"
        || name == "docker-compose.yaml"
    {
        out.docker.push(path.to_path_buf());
    }

    // CI workflow files
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy();
    let rel_unix = rel.replace('\\', "/");
    if rel_unix.contains(".github/workflows/") && (name.ends_with(".yml") || name.ends_with(".yaml"))
    {
        out.ci.push(path.to_path_buf());
    } else if (name.ends_with(".yml") || name.ends_with(".yaml")) && !rel_unix.contains(".github/workflows/") {
        // Non-CI YAML/YML → config bucket (may contain runs-on for platform inference)
        out.config.push(path.to_path_buf());
    }

    // Config files (by extension)
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        match ext {
            "conf" | "json" | "tf" => {
                out.config.push(path.to_path_buf());
            }
            _ => {}
        }
    }

    // Source files
    if out.source.len() < max_source {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if Lang::from_extension(ext).is_some() {
                if skip_tests && is_test_path(&rel_unix) {
                    return;
                }
                if let Some(pf) = path_filter {
                    if !rel_unix.contains(pf) {
                        return;
                    }
                }
                out.source.push(path.to_path_buf());
            }
        }
    }
}

fn is_test_path(rel: &str) -> bool {
    rel.contains("/__tests__/")
        || rel.contains("/test/")
        || rel.contains("/tests/")
        || rel.contains("/mocks/")
        || rel.ends_with(".test.js")
        || rel.ends_with(".spec.js")
        || rel.ends_with(".test.ts")
        || rel.ends_with(".spec.ts")
        || rel.ends_with("_test.py")
        || rel.rsplit('/').next().unwrap_or("").starts_with("test_")
        || rel.ends_with("_test.go")
        || rel.contains("/src/test/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excluded_dirs_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("foo.js"), "fetch()").unwrap();
        std::fs::write(dir.path().join("app.js"), "fetch()").unwrap();
        let files = collect(dir.path(), 1000, false, None);
        assert_eq!(files.source.len(), 1);
    }

    #[test]
    fn classifies_docker_and_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:22").unwrap();
        std::fs::write(dir.path().join("nginx.conf"), "server {}").unwrap();
        std::fs::write(dir.path().join("main.tf"), "resource {}").unwrap();
        let files = collect(dir.path(), 1000, false, None);
        assert_eq!(files.docker.len(), 1);
        assert!(files.config.len() >= 2);
    }

    #[test]
    fn classifies_ci_workflows() {
        let dir = tempfile::tempdir().unwrap();
        let wf = dir.path().join(".github/workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(wf.join("ci.yml"), "runs-on: ubuntu-latest").unwrap();
        let files = collect(dir.path(), 1000, false, None);
        assert_eq!(files.ci.len(), 1);
    }

    #[test]
    fn max_source_respected() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            std::fs::write(dir.path().join(format!("f{i}.js")), "fetch()").unwrap();
        }
        let files = collect(dir.path(), 3, false, None);
        assert_eq!(files.source.len(), 3);
    }

    #[test]
    fn skip_tests_filters() {
        let dir = tempfile::tempdir().unwrap();
        let tests = dir.path().join("__tests__");
        std::fs::create_dir_all(&tests).unwrap();
        std::fs::write(tests.join("foo.test.js"), "fetch()").unwrap();
        std::fs::write(dir.path().join("app.js"), "fetch()").unwrap();
        let files = collect(dir.path(), 1000, true, None);
        assert_eq!(files.source.len(), 1);
    }

    #[test]
    fn path_filter_works() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("app.js"), "fetch()").unwrap();
        std::fs::write(dir.path().join("lib.js"), "fetch()").unwrap();
        let files = collect(dir.path(), 1000, false, Some("src"));
        assert_eq!(files.source.len(), 1);
    }
}
