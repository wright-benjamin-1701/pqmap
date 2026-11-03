//! Infrastructure / topology detection (plan 05).
//!
//! We read IaC + reverse-proxy configs *statically* (no cluster access, no
//! `cdk synth`), and classify each discovered component. The pipeline applies
//! topology inference (outermost terminator + misleading-code finding) on top
//! of the components this module produces.

use std::path::{Path, PathBuf};

/// One infrastructure component (plan 05 `InfraComponent`).
#[derive(Debug, Clone, PartialEq)]
pub struct InfraComponent {
    /// Stable id (vendor + kind + name).
    pub id: String,
    /// `aws`, `cf`, `nginx`, `envoy`, …
    pub vendor: String,
    /// `alb`, `edge`, `reverse_proxy`, …
    pub kind: String,
    /// Logical name (from the IaC / config, when present).
    pub name: String,
    /// Does this component terminate TLS for the service it fronts?
    pub terminates_tls: bool,
    /// Higher = more outer (closer to the internet). Plan 01 invariant #2:
    /// the outermost infra component wins; the inner is `upstream_owner`.
    ///   3 — cloud edge (ALB, CloudFront, Cloudflare edge)
    ///   2 — reverse proxy / gateway (nginx, Envoy, sidecar)
    ///   0 — code / library (not an infra component)
    pub outerness: u8,
    /// Upstream components (what it proxies to) — ids.
    pub upstream: Vec<String>,
    /// Downstream components (what fronts it) — ids.
    pub downstream: Vec<String>,
    /// Config evidence: `file:line` references.
    pub config_evidence: Vec<String>,
    /// Source file (relative) where it was discovered.
    pub file: String,
    pub line: u32,
    /// Confidence (0..1).
    pub confidence: f32,
    /// Whether PQ groups (e.g. X25519MLKEM768) were detected in this
    /// component's configuration.
    pub pq_groups_detected: bool,
}

impl InfraComponent {
    fn outerness_for(kind: &str) -> u8 {
        match kind {
            // Cloud edge / LB are the outermost terminators we model.
            "alb" | "cloudfront" | "edge" => 3,
            // Reverse proxies / gateways sit inside a cloud LB when both are
            // present; they are the innermost when alone.
            "reverse_proxy" | "gateway" => 2,
            _ => 0,
        }
    }

    fn new(vendor: &str, kind: &str, rel: &str, confidence: f32) -> Self {
        Self {
            id: format!("{}::{}::{}", vendor, kind, rel),
            vendor: vendor.to_string(),
            kind: kind.to_string(),
            name: kind.to_string(),
            terminates_tls: matches!(
                kind,
                "alb" | "cloudfront" | "edge" | "reverse_proxy" | "gateway"
            ),
            outerness: Self::outerness_for(kind),
            upstream: vec![],
            downstream: vec![],
            config_evidence: vec![format!("{}:1", rel)],
            file: rel.to_string(),
            line: 1,
            confidence,
            pq_groups_detected: false,
        }
    }
}

/// The detector over a tree of config files.
#[derive(Debug, Default)]
pub struct IaCDetector {
    components: Vec<InfraComponent>,
}

impl IaCDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run over a directory tree. Looks for:
    ///   - `nginx.conf` / `*.conf` containing `server {`
    ///   - `cloudfront.json` (AWS), `cloudflare.json` (CF)
    ///   - Terraform `aws_alb` / `aws_lb` / `aws_cloudfront` resources
    pub fn run(&mut self, root: &Path) {
        let mut files: Vec<PathBuf> = Vec::new();
        Self::walk(root, &mut files);
        self.run_on_files(root, &files);
    }

    /// Run over pre-collected config files (from the unified walk).
    pub fn run_on_files(&mut self, root: &Path, files: &[PathBuf]) {
        for f in files {
            let rel = f.strip_prefix(root).unwrap_or(f.as_path());
            let rel = rel.to_string_lossy().into_owned();
            let Ok(content) = std::fs::read_to_string(&f) else {
                continue;
            };
            let name = f
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();

            if name.contains("nginx") || (name.ends_with(".conf") && content.contains("server")) {
                let mut comp = InfraComponent::new(
                    "nginx",
                    "reverse_proxy",
                    &rel,
                    0.7,
                );
                // Detect PQ groups in nginx ssl_conf_command (e.g. X25519MLKEM768).
                if content.contains("MLKEM") || content.contains("mlkem") {
                    comp.pq_groups_detected = true;
                }
                self.components.push(comp);
            }
            if name == "cloudfront.json" {
                self.components
                    .push(InfraComponent::new("aws", "cloudfront", &rel, 0.8));
            }
            if name == "cloudflare.json" {
                self.components
                    .push(InfraComponent::new("cf", "edge", &rel, 0.8));
            }
            let is_tf = name.ends_with(".tf") || name == "cdk.json" || name == "template.yaml";
            if is_tf && (content.contains("aws_alb") || content.contains("aws_lb")) {
                self.components
                    .push(InfraComponent::new("aws", "alb", &rel, 0.7));
            }
            if is_tf && content.contains("aws_cloudfront") {
                self.components.push(InfraComponent::new(
                    "aws",
                    "cloudfront",
                    &rel,
                    0.75,
                ));
            }
        }
        self.components.sort_by(|a, b| a.id.cmp(&b.id));
    }

    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                let n = p
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if matches!(n.as_str(), "node_modules" | ".git" | "target" | "dist" | "saas" | "fixtures"
                    | ".venv" | "venv" | "__pycache__" | "obj" | "bin" | "publish" | "TestResults") {
                    continue;
                }
                Self::walk(&p, out);
            } else if let Some(ext) = p.extension() {
                let ext = ext.to_string_lossy().into_owned();
                if matches!(
                    ext.as_str(),
                    "conf" | "json" | "tf" | "yml" | "yaml" | "tf.json"
                ) {
                    out.push(p);
                }
            }
        }
    }

    pub fn into_components(self) -> Vec<InfraComponent> {
        self.components
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_terminates_tls_for_alb() {
        let c = InfraComponent::new("aws", "alb", "infra/main.tf", 0.7);
        assert!(c.terminates_tls);
        assert_eq!(c.outerness, 3);
    }

    #[test]
    fn component_does_not_terminate_tls_for_unknown() {
        let c = InfraComponent::new("custom", "app", "app.yaml", 0.5);
        assert!(!c.terminates_tls);
        assert_eq!(c.outerness, 0);
    }

    #[test]
    fn iac_detector_finds_nginx() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("nginx.conf");
        std::fs::write(&conf, "server { listen 443 ssl; }").unwrap();
        let mut det = IaCDetector::new();
        det.run(dir.path());
        let comps = det.into_components();
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].vendor, "nginx");
        assert_eq!(comps[0].kind, "reverse_proxy");
    }

    #[test]
    fn iac_detector_finds_nginx_pq_groups() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("nginx.conf");
        std::fs::write(
            &conf,
            "server {\n  listen 443 ssl;\n  ssl_conf_command Groups X25519MLKEM768:X25519;\n}",
        )
        .unwrap();
        let mut det = IaCDetector::new();
        det.run(dir.path());
        let comps = det.into_components();
        assert_eq!(comps.len(), 1);
        assert!(comps[0].pq_groups_detected);
    }

    #[test]
    fn iac_detector_nginx_without_pq_groups() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("nginx.conf");
        std::fs::write(&conf, "server { listen 443 ssl; }").unwrap();
        let mut det = IaCDetector::new();
        det.run(dir.path());
        let comps = det.into_components();
        assert_eq!(comps.len(), 1);
        assert!(!comps[0].pq_groups_detected);
    }

    #[test]
    fn iac_detector_finds_terraform_alb() {
        let dir = tempfile::tempdir().unwrap();
        let infra = dir.path().join("infra");
        std::fs::create_dir_all(&infra).unwrap();
        std::fs::write(
            infra.join("main.tf"),
            "resource \"aws_alb\" \"main\" { name = \"test\" }",
        )
        .unwrap();
        let mut det = IaCDetector::new();
        det.run(dir.path());
        let comps = det.into_components();
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].vendor, "aws");
        assert_eq!(comps[0].kind, "alb");
    }
}
