# pqmap

Post-Quantum Cryptography migration control plane. Scans your codebase for TLS
and cryptographic usage, scores quantum readiness, and generates a prioritised
remediation plan.

## What it does

`pqmap` builds an **EndpointGraph** — a map of every outbound network edge in
your application — and enriches each edge with:

- **TLS stack resolution** — which library/runtime actually terminates TLS
  (OpenSSL, BoringSSL, SChannel, platform default, or an infra component like
  ALB/nginx).
- **PQ readiness scoring** — per-edge and composite scores for confidentiality,
  authentication, and crypto-agility.
- **Misleading-code detection** — flags code that *looks* like it owns TLS but
  is actually behind an infra terminator.
- **Live probing** — optional TLS handshake against real endpoints to verify
  PQ negotiation.
- **Remediation ladder** — prioritised, actionable steps to reach PQ readiness.

Outputs include a structured JSON graph, SARIF for IDE/CI integration, and
CycloneDX CBOM.

## Quick start

```bash
cargo build --release
./target/release/pqmap scan ./my-project
```

## Commands

| Command   | Description                                       |
|-----------|---------------------------------------------------|
| `scan`    | Build the EndpointGraph from source + IaC + KB    |
| `score`   | Re-score a stored graph                           |
| `fix`     | Emit a prioritised remediation plan               |
| `probe`   | Live-verify TLS handshakes against real endpoints |
| `explain` | Print the full resolution chain for a single edge |

## Workspace crates

| Crate       | Role                                            |
|-------------|--------------------------------------------------|
| `core`      | Shared types — graph, edges, scoring, SARIF      |
| `kb`        | Knowledge base: runtime → TLS stack resolver     |
| `analyzers` | Source + IaC walkers, language detection, catalog |
| `scoring`   | Edge scoring engine and remediation evaluator    |
| `probe`     | Live TLS handshake prober                        |
| `cli`       | User-facing CLI (`pqmap` binary)                 |

## Supported languages

Go, Java, Python, TypeScript/JavaScript, C#, Rust.

## License

Copyright (c) 2024-present Benjamin Wright. All rights reserved.

This software is available under a **dual license**:

1. **Open source** — [GNU Affero General Public License v3.0](LICENSE)
   (AGPL-3.0-only). You may use, modify, and distribute this software under the
   terms of the AGPL. Any network-accessible service built with this code must
   also be released under the AGPL.

2. **Commercial** — A proprietary license is available for organisations that
   cannot comply with the AGPL. Contact the author for terms.

See [LICENSE](LICENSE) for the full AGPL-3.0 text.
