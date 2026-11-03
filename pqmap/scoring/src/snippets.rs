//! Runtime-specific remediation snippets (plan 06 extension).
//!
//! Given a rung, a network edge, and the finding axis, `generate()` returns
//! copy-pasteable code snippets tailored to the edge's language, runtime,
//! framework, and OS. The snippets are informational proposals
//! (`dry_run_default = true`); they never auto-apply.

use pq_core::{
    FindingAxis, LanguageTag, NetworkEdge, RemediationSnippet, Rung, SnippetKind, SourceRef,
};

/// Produce remediation snippets for the given rung, edge, and axis.
pub fn generate(rung: Rung, edge: &NetworkEdge, _axis: FindingAxis) -> Vec<RemediationSnippet> {
    let lang = source_language(edge);
    let runtime = edge
        .runtime
        .as_ref()
        .and_then(|r| r.name.as_deref())
        .unwrap_or("");
    let framework = edge.framework.as_deref().unwrap_or("");
    let os = edge
        .runtime
        .as_ref()
        .and_then(|r| r.os.as_deref())
        .unwrap_or("linux");

    match rung {
        Rung::R1Dependency => rung1_snippets(lang, runtime, framework, os),
        Rung::R2Config => rung2_snippets(lang, runtime, framework, os),
        Rung::R3Iac => rung3_snippets(),
        Rung::R4Gateway => rung4_snippets(),
    }
}

fn source_language(edge: &NetworkEdge) -> LanguageTag {
    match &edge.source {
        SourceRef::Code { language, .. } => *language,
        _ => LanguageTag::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Rung 1 — Dependency / base-image upgrade
// ---------------------------------------------------------------------------

fn rung1_snippets(
    lang: LanguageTag,
    _runtime: &str,
    _framework: &str,
    _os: &str,
) -> Vec<RemediationSnippet> {
    match lang {
        LanguageTag::Js | LanguageTag::Ts => rung1_node(),
        LanguageTag::Csharp => rung1_dotnet(),
        LanguageTag::Python => rung1_python(),
        LanguageTag::Java => rung1_java(),
        LanguageTag::Go => rung1_go(),
        LanguageTag::Rust => rung1_rust(),
        _ => rung1_fallback(),
    }
}

fn rung1_node() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Upgrade Node.js base image to 22".into(),
            language: "dockerfile".into(),
            code: "FROM node:22-slim\n".into(),
            kind: SnippetKind::DockerfileChange,
            doc_url: Some("https://nodejs.org/en/download".into()),
        },
        RemediationSnippet {
            title: "Pin engines in package.json".into(),
            language: "json".into(),
            code: r#"{
  "engines": {
    "node": ">=22.0.0"
  }
}"#
            .into(),
            kind: SnippetKind::DependencyUpgrade,
            doc_url: None,
        },
        RemediationSnippet {
            title: "Pin .nvmrc".into(),
            language: "text".into(),
            code: "22\n".into(),
            kind: SnippetKind::ConfigChange,
            doc_url: None,
        },
    ]
}

fn rung1_dotnet() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Upgrade .NET SDK base image to 10.0".into(),
            language: "dockerfile".into(),
            code: "FROM mcr.microsoft.com/dotnet/sdk:10.0\n".into(),
            kind: SnippetKind::DockerfileChange,
            doc_url: Some("https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/overview".into()),
        },
        RemediationSnippet {
            title: "Set TargetFramework to net10.0".into(),
            language: "xml".into(),
            code: "<PropertyGroup>\n  <TargetFramework>net10.0</TargetFramework>\n</PropertyGroup>\n".into(),
            kind: SnippetKind::DependencyUpgrade,
            doc_url: None,
        },
        RemediationSnippet {
            title: "Pin SDK version in global.json".into(),
            language: "json".into(),
            code: r#"{
  "sdk": {
    "version": "10.0.100",
    "rollForward": "latestFeature"
  }
}"#
            .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: None,
        },
    ]
}

fn rung1_python() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Use a base image with OpenSSL 3.5+".into(),
            language: "dockerfile".into(),
            code: "\
# Use a distro that ships OpenSSL >= 3.5 (e.g. Ubuntu 25.04+)\n\
FROM python:3.13-slim\n\
# Verify at build time:\n\
RUN python -c \"import ssl; print(ssl.OPENSSL_VERSION)\"\n"
                .into(),
            kind: SnippetKind::DockerfileChange,
            doc_url: Some("https://docs.python.org/3/library/ssl.html".into()),
        },
        RemediationSnippet {
            title: "Verify OpenSSL version at runtime".into(),
            language: "python".into(),
            code: "\
import ssl\nassert ssl.OPENSSL_VERSION_INFO >= (3, 5, 0), (\n    f\"Need OpenSSL >= 3.5, got {ssl.OPENSSL_VERSION}\"\n)\n"
                .into(),
            kind: SnippetKind::ShellCommand,
            doc_url: None,
        },
    ]
}

fn rung1_java() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Upgrade JVM base image to 21".into(),
            language: "dockerfile".into(),
            code: "FROM eclipse-temurin:21-jre-alpine\n".into(),
            kind: SnippetKind::DockerfileChange,
            doc_url: Some("https://adoptium.net/temurin/releases/".into()),
        },
        RemediationSnippet {
            title: "Add BouncyCastle PQC provider (Maven)".into(),
            language: "xml".into(),
            code: "\
<dependency>\n\
  <groupId>org.bouncycastle</groupId>\n\
  <artifactId>bcprov-jdk18on</artifactId>\n\
  <version>1.79</version>\n\
</dependency>\n\
<dependency>\n\
  <groupId>org.bouncycastle</groupId>\n\
  <artifactId>bctls-jdk18on</artifactId>\n\
  <version>1.79</version>\n\
</dependency>\n"
                .into(),
            kind: SnippetKind::DependencyUpgrade,
            doc_url: Some("https://www.bouncycastle.org/latest_releases.html".into()),
        },
        RemediationSnippet {
            title: "Add BouncyCastle PQC provider (Gradle)".into(),
            language: "groovy".into(),
            code: "\
implementation 'org.bouncycastle:bcprov-jdk18on:1.79'\n\
implementation 'org.bouncycastle:bctls-jdk18on:1.79'\n"
                .into(),
            kind: SnippetKind::DependencyUpgrade,
            doc_url: None,
        },
    ]
}

fn rung1_go() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Upgrade Go base image to 1.24".into(),
            language: "dockerfile".into(),
            code: "\
FROM golang:1.24-alpine AS build\n\
ENV GOEXPERIMENT=mlkem\n"
                .into(),
            kind: SnippetKind::DockerfileChange,
            doc_url: Some("https://go.dev/doc/go1.24#crypto/tls".into()),
        },
        RemediationSnippet {
            title: "Set Go version in go.mod".into(),
            language: "text".into(),
            code: "go 1.24\n".into(),
            kind: SnippetKind::DependencyUpgrade,
            doc_url: None,
        },
        RemediationSnippet {
            title: "Alternative: use circl for PQ KEM".into(),
            language: "shell".into(),
            code: "go get github.com/cloudflare/circl@latest\n".into(),
            kind: SnippetKind::DependencyUpgrade,
            doc_url: Some("https://github.com/cloudflare/circl".into()),
        },
    ]
}

fn rung1_rust() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Use OpenSSL 3.5+ or rustls with aws_lc_rs".into(),
            language: "toml".into(),
            code: "\
# Option A: link against OpenSSL >= 3.5 (system or vendored)\n\
[dependencies]\n\
openssl = { version = \"0.10\", features = [\"vendored\"] }\n\
\n\
# Option B: use rustls with aws-lc-rs backend\n\
[dependencies]\n\
rustls = { version = \"0.23\", features = [\"aws_lc_rs\"] }\n"
                .into(),
            kind: SnippetKind::DependencyUpgrade,
            doc_url: Some("https://docs.rs/rustls/latest/rustls/".into()),
        },
    ]
}

fn rung1_fallback() -> Vec<RemediationSnippet> {
    vec![RemediationSnippet {
        title: "Upgrade to OpenSSL 3.5+".into(),
        language: "shell".into(),
        code: "\
# Install OpenSSL 3.5+ from source or package manager\n\
# Debian/Ubuntu (when available):\n\
apt-get update && apt-get install -y libssl-dev\n\
# Verify:\n\
openssl version   # should show >= 3.5\n"
            .into(),
        kind: SnippetKind::ShellCommand,
        doc_url: Some("https://www.openssl.org/source/".into()),
    }]
}

// ---------------------------------------------------------------------------
// Rung 2 — Config flip (PQ groups enabled)
// ---------------------------------------------------------------------------

fn rung2_snippets(
    lang: LanguageTag,
    _runtime: &str,
    _framework: &str,
    os: &str,
) -> Vec<RemediationSnippet> {
    let mut out = match lang {
        LanguageTag::Js | LanguageTag::Ts => rung2_node(),
        LanguageTag::Csharp => rung2_dotnet(os),
        LanguageTag::Python => rung2_python(),
        LanguageTag::Java => rung2_java(),
        LanguageTag::Go => rung2_go(),
        _ => vec![],
    };
    // Every rung-2 edge can also benefit from an nginx PQ config.
    out.push(RemediationSnippet {
        title: "nginx: enable PQ groups".into(),
        language: "nginx".into(),
        code: "\
ssl_conf_command Groups X25519MLKEM768:X25519:prime256v1;\n\
ssl_protocols TLSv1.3;\n"
            .into(),
        kind: SnippetKind::ConfigChange,
        doc_url: Some("https://nginx.org/en/docs/http/ngx_http_ssl_module.html".into()),
    });
    out
}

fn rung2_node() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Enable PQ groups on tls.connect / https.Agent".into(),
            language: "javascript".into(),
            code: "\
const tls = require('node:tls');\n\
\n\
const socket = tls.connect(443, 'example.com', {\n\
  ecdhCurve: 'X25519MLKEM768:X25519',\n\
  minVersion: 'TLSv1.3',\n\
});\n\
\n\
// Or via https.Agent:\n\
const https = require('node:https');\n\
const agent = new https.Agent({\n\
  ecdhCurve: 'X25519MLKEM768:X25519',\n\
  minVersion: 'TLSv1.3',\n\
});\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: Some("https://nodejs.org/api/tls.html".into()),
        },
    ]
}

fn rung2_dotnet(os: &str) -> Vec<RemediationSnippet> {
    let mut out = vec![RemediationSnippet {
        title: "Enable PQ via SslClientAuthenticationOptions (.NET 10+, Linux)".into(),
        language: "csharp".into(),
        code: "\
using System.Net.Security;\nusing System.Security.Authentication;\n\n\
var options = new SslClientAuthenticationOptions\n{\n\
    TargetHost = \"example.com\",\n\
    EnabledSslProtocols = SslProtocols.Tls13,\n\
};\n\n\
// Kestrel:\n\
builder.WebHost.ConfigureKestrel(k =>\n{\n\
    k.ConfigureHttpsDefaults(https =>\n    {\n\
        https.SslProtocols = SslProtocols.Tls13;\n    });\n\
});\n\n\
// Environment variable (app-wide):\n\
// DOTNET_SYSTEM_NET_SECURITY_TLSCIPHER=\"TLS_AES_256_GCM_SHA384\"\n"
            .into(),
        kind: SnippetKind::ConfigChange,
        doc_url: Some("https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslclientauthenticationoptions".into()),
    }];

    if os == "windows" {
        out.push(RemediationSnippet {
            title: "Note: Schannel (Windows) PQ support".into(),
            language: "text".into(),
            code: "\
Windows Schannel PQ KEM support depends on the OS version.\n\
As of Windows 11 24H2 / Server 2025, PQ hybrid is available\n\
via Schannel but may not be enabled by default. Check:\n\
  Get-TlsCipherSuite | Where-Object { $_.Name -match 'MLKEM' }\n\
If unavailable, consider an nginx/Envoy PQ sidecar (Rung 3/4).\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: None,
        });
    }
    out
}

fn rung2_python() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Enable TLS 1.3 with PQ groups (stdlib ssl)".into(),
            language: "python".into(),
            code: "\
import ssl\n\n\
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n\
ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n\
# OpenSSL 3.5+ will negotiate PQ groups automatically.\n\
# To verify:\n\
# ctx.get_ciphers()  — look for TLS_AES_256_GCM_SHA384 etc.\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: Some("https://docs.python.org/3/library/ssl.html".into()),
        },
        RemediationSnippet {
            title: "Enable PQ with httpx".into(),
            language: "python".into(),
            code: "\
import httpx\nimport ssl\n\n\
ctx = ssl.create_default_context()\n\
ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n\
client = httpx.Client(verify=ctx)\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: None,
        },
    ]
}

fn rung2_java() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Register BouncyCastle JSSE provider".into(),
            language: "java".into(),
            code: "\
import java.security.Security;\nimport org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;\n\n\
// Register at startup:\n\
Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: Some("https://www.bouncycastle.org/documentation/documentation-java/".into()),
        },
        RemediationSnippet {
            title: "Set PQ named groups via JVM argument".into(),
            language: "shell".into(),
            code: "\
java -Djdk.tls.namedGroups=\"X25519MLKEM768,X25519,secp256r1\" -jar app.jar\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: None,
        },
        RemediationSnippet {
            title: "Spring Boot application.yml TLS config".into(),
            language: "yaml".into(),
            code: "\
server:\n\
  ssl:\n\
    protocol: TLSv1.3\n\
    provider: BCJSSE\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: None,
        },
    ]
}

fn rung2_go() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "Enable PQ in tls.Config".into(),
            language: "go".into(),
            code: "\
import \"crypto/tls\"\n\n\
cfg := &tls.Config{\n\
\tMinVersion:       tls.VersionTLS13,\n\
\tCurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},\n\
}\n"
                .into(),
            kind: SnippetKind::ConfigChange,
            doc_url: Some("https://go.dev/doc/go1.24#crypto/tls".into()),
        },
        RemediationSnippet {
            title: "Set GOEXPERIMENT for ML-KEM".into(),
            language: "shell".into(),
            code: "export GOEXPERIMENT=mlkem\n".into(),
            kind: SnippetKind::ConfigChange,
            doc_url: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Rung 3 — Infrastructure / IaC
// ---------------------------------------------------------------------------

fn rung3_snippets() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "CloudFront PQ distribution (Terraform)".into(),
            language: "hcl".into(),
            code: "\
resource \"aws_cloudfront_distribution\" \"pq\" {\n\
  # ... existing config ...\n\n\
  viewer_certificate {\n\
    cloudfront_default_certificate = false\n\
    acm_certificate_arn            = aws_acm_certificate.cert.arn\n\
    ssl_support_method             = \"sni-only\"\n\
    minimum_protocol_version       = \"TLSv1.3_2024\"\n\
  }\n\n\
  # CloudFront automatically negotiates PQ hybrid (X25519MLKEM768)\n\
  # with compatible clients when TLS 1.3 is enabled.\n\
}\n"
                .into(),
            kind: SnippetKind::IaCChange,
            doc_url: Some("https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html".into()),
        },
        RemediationSnippet {
            title: "CloudFront PQ distribution (AWS CDK)".into(),
            language: "typescript".into(),
            code: "\
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';\n\n\
new cloudfront.Distribution(this, 'PqDist', {\n\
  defaultBehavior: { origin },\n\
  minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,\n\
  // CloudFront auto-negotiates PQ hybrid with TLS 1.3 clients.\n\
});\n"
                .into(),
            kind: SnippetKind::IaCChange,
            doc_url: None,
        },
        RemediationSnippet {
            title: "Cloudflare zone TLS 1.3 (Terraform)".into(),
            language: "hcl".into(),
            code: "\
resource \"cloudflare_zone_settings_override\" \"pq\" {\n\
  zone_id = var.zone_id\n\
  settings {\n\
    min_tls_version = \"1.3\"\n\
  }\n\
}\n\
# Cloudflare edge negotiates PQ hybrid automatically with TLS 1.3.\n"
                .into(),
            kind: SnippetKind::IaCChange,
            doc_url: Some("https://developers.cloudflare.com/ssl/quantum-safe-tls/".into()),
        },
        RemediationSnippet {
            title: "nginx reverse proxy with PQ groups".into(),
            language: "nginx".into(),
            code: "\
server {\n\
    listen 443 ssl;\n\
    ssl_protocols TLSv1.3;\n\
    ssl_conf_command Groups X25519MLKEM768:X25519:prime256v1;\n\n\
    location / {\n\
        proxy_pass http://upstream_app;\n\
    }\n\
}\n"
                .into(),
            kind: SnippetKind::IaCChange,
            doc_url: Some("https://nginx.org/en/docs/http/ngx_http_ssl_module.html".into()),
        },
    ]
}

// ---------------------------------------------------------------------------
// Rung 4 — PQC Gateway sidecar
// ---------------------------------------------------------------------------

fn rung4_snippets() -> Vec<RemediationSnippet> {
    vec![
        RemediationSnippet {
            title: "PQ Gateway sidecar (docker-compose)".into(),
            language: "yaml".into(),
            code: "\
services:\n\
  app:\n\
    build: .\n\
    # App talks plain HTTP to the sidecar on localhost\n\
    environment:\n\
      - UPSTREAM_URL=http://localhost:8080\n\n\
  pq-gateway:\n\
    image: nginx:1.27-alpine\n\
    ports:\n\
      - \"443:443\"\n\
    volumes:\n\
      - ./nginx-pq.conf:/etc/nginx/conf.d/default.conf:ro\n\
      - ./certs:/etc/nginx/certs:ro\n\
    depends_on:\n\
      - app\n"
                .into(),
            kind: SnippetKind::IaCChange,
            doc_url: None,
        },
        RemediationSnippet {
            title: "Envoy PQ TLS sidecar".into(),
            language: "yaml".into(),
            code: "\
static_resources:\n\
  listeners:\n\
    - name: pq_listener\n\
      address:\n\
        socket_address: { address: 0.0.0.0, port_value: 443 }\n\
      filter_chains:\n\
        - transport_socket:\n\
            name: envoy.transport_sockets.tls\n\
            typed_config:\n\
              \"@type\": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext\n\
              common_tls_context:\n\
                tls_params:\n\
                  tls_minimum_protocol_version: TLSv1_3\n\
                  ecdh_curves:\n\
                    - X25519MLKEM768\n\
                    - X25519\n\
          filters:\n\
            - name: envoy.filters.network.http_connection_manager\n\
              typed_config:\n\
                \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\n\
                route_config:\n\
                  virtual_hosts:\n\
                    - name: app\n\
                      domains: [\"*\"]\n\
                      routes:\n\
                        - match: { prefix: \"/\" }\n\
                          route: { cluster: app_backend }\n\
  clusters:\n\
    - name: app_backend\n\
      load_assignment:\n\
        cluster_name: app_backend\n\
        endpoints:\n\
          - lb_endpoints:\n\
              - endpoint:\n\
                  address:\n\
                    socket_address: { address: 127.0.0.1, port_value: 8080 }\n"
                .into(),
            kind: SnippetKind::IaCChange,
            doc_url: Some("https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto".into()),
        },
        RemediationSnippet {
            title: "Kubernetes sidecar injection patch".into(),
            language: "yaml".into(),
            code: "\
apiVersion: apps/v1\n\
kind: Deployment\n\
metadata:\n\
  name: app\n\
spec:\n\
  template:\n\
    spec:\n\
      containers:\n\
        - name: app\n\
          # ... existing app container ...\n\
        - name: pq-gateway\n\
          image: envoyproxy/envoy:v1.31-latest\n\
          ports:\n\
            - containerPort: 443\n\
          volumeMounts:\n\
            - name: envoy-config\n\
              mountPath: /etc/envoy\n\
            - name: tls-certs\n\
              mountPath: /etc/certs\n\
      volumes:\n\
        - name: envoy-config\n\
          configMap:\n\
            name: pq-envoy-config\n\
        - name: tls-certs\n\
          secret:\n\
            secretName: pq-tls-certs\n"
                .into(),
            kind: SnippetKind::IaCChange,
            doc_url: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::{
        edge_id, DestinationRef, Direction, Evidence, Protocol, SourceRef, TlsCapability,
        TlsImplementation, TlsStack, PqAxisState, Provenance,
    };

    fn make_edge(lang: LanguageTag, runtime_name: &str, os: &str) -> NetworkEdge {
        let src = SourceRef::Code {
            file: "app.rs".into(),
            line: 1,
            col: 1,
            symbol: "main".into(),
            language: lang,
        };
        let dst = DestinationRef::ResolvedTarget {
            host: "example.com".into(),
            port: 443,
            scheme: "https".into(),
        };
        let id = edge_id(&src, &dst, &Protocol::Https);
        let stack = TlsStack {
            impl_kind: TlsImplementation::OpenSSL,
            version: Some("3.0".into()),
            os: Some(os.into()),
            pq_kem: TlsCapability {
                state: PqAxisState::PqUnavailable,
                groups: vec![],
                source_url: "u".into(),
                as_of: "d".into(),
            },
            pq_sig: TlsCapability {
                state: PqAxisState::PqUnavailable,
                groups: vec![],
                source_url: "u".into(),
                as_of: "d".into(),
            },
            provenance: Provenance {
                source_url: "u".into(),
                as_of: "d".into(),
            },
            evidence: vec![],
        };
        NetworkEdge {
            id,
            protocol: Protocol::Https,
            direction: Direction::Outbound,
            source: src,
            destination: dst,
            framework: None,
            tls_provider: None,
            upstream_owner: None,
            runtime: Some(pq_core::RuntimeFacts {
                tfm: None,
                os: Some(os.into()),
                name: Some(runtime_name.into()),
                version: None,
                node_openssl: None,
                evidence: vec![],
            }),
            tls_stack: Some(stack),
            misleading_code: None,
            handshake: None,
            pq: None,
            confidence: 0.9,
            evidence: vec![Evidence::Kb {
                row_id: "r".into(),
                source_url: "u".into(),
                as_of: "d".into(),
            }],
            resolution: vec![],
        }
    }

    #[test]
    fn r1_node_produces_dockerfile_and_package_json() {
        let e = make_edge(LanguageTag::Js, "node", "linux");
        let snips = generate(Rung::R1Dependency, &e, FindingAxis::Confidentiality);
        assert!(snips.len() >= 2, "expect Dockerfile + package.json snippets");
        assert!(snips.iter().any(|s| s.kind == SnippetKind::DockerfileChange));
        assert!(snips.iter().any(|s| s.kind == SnippetKind::DependencyUpgrade));
    }

    #[test]
    fn r1_dotnet_produces_csproj() {
        let e = make_edge(LanguageTag::Csharp, "dotnet", "linux");
        let snips = generate(Rung::R1Dependency, &e, FindingAxis::Confidentiality);
        assert!(snips.iter().any(|s| s.code.contains("net10.0")));
    }

    #[test]
    fn r1_java_produces_bc_deps() {
        let e = make_edge(LanguageTag::Java, "jvm", "linux");
        let snips = generate(Rung::R1Dependency, &e, FindingAxis::Confidentiality);
        assert!(snips.iter().any(|s| s.code.contains("bouncycastle")));
    }

    #[test]
    fn r1_go_produces_dockerfile_and_gomod() {
        let e = make_edge(LanguageTag::Go, "go", "linux");
        let snips = generate(Rung::R1Dependency, &e, FindingAxis::Confidentiality);
        assert!(snips.iter().any(|s| s.code.contains("golang:1.24")));
        assert!(snips.iter().any(|s| s.code.contains("go 1.24")));
    }

    #[test]
    fn r2_java_produces_bc_jsse() {
        let e = make_edge(LanguageTag::Java, "jvm", "linux");
        let snips = generate(Rung::R2Config, &e, FindingAxis::Confidentiality);
        assert!(snips.iter().any(|s| s.code.contains("BouncyCastleJsseProvider")));
    }

    #[test]
    fn r2_includes_nginx_snippet() {
        let e = make_edge(LanguageTag::Python, "python", "linux");
        let snips = generate(Rung::R2Config, &e, FindingAxis::Confidentiality);
        assert!(snips.iter().any(|s| s.language == "nginx"));
    }

    #[test]
    fn r3_produces_cloudfront() {
        let e = make_edge(LanguageTag::Unknown, "openssl", "linux");
        let snips = generate(Rung::R3Iac, &e, FindingAxis::Confidentiality);
        assert!(snips.iter().any(|s| s.code.contains("cloudfront")));
    }

    #[test]
    fn r4_produces_three_sidecar_variants() {
        let e = make_edge(LanguageTag::Unknown, "openssl", "linux");
        let snips = generate(Rung::R4Gateway, &e, FindingAxis::Confidentiality);
        assert_eq!(snips.len(), 3, "expect docker-compose, envoy, k8s sidecar");
    }

    #[test]
    fn unknown_language_gets_fallback() {
        let e = make_edge(LanguageTag::Unknown, "openssl", "linux");
        let snips = generate(Rung::R1Dependency, &e, FindingAxis::Confidentiality);
        assert!(!snips.is_empty(), "unknown language should still get a fallback snippet");
        assert!(snips[0].code.contains("openssl"));
    }
}
