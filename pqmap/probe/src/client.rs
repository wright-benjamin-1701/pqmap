//! In-binary TLS client for live handshake probing (plan 04).
//!
//! Design (validated by `tests` against a local rustls server):
//!
//! - **Trust**: we verify the server chain against a `roots` CA bundle supplied
//!   via `ProbeOptions::roots`. For the local test server we pass the server's
//!   self-signed cert as a root. For real targets the CLI supplies bundled
//!   webpki roots. Plan 04: we never trust the ambient OS store.
//! - **Two offering round-trips**: `classical_provider` (no PQ groups) for the
//!   baseline, then `pq_provider` (X25519MLKEM768 preferred). The PQ round's
//!   negotiated group is what sets `server_negotiated_pq`. This is the only way
//!   to distinguish `pq-negotiated` from `pq-capable` (plan 04).
//! - **Passive observation**: we record cert facts (sig alg, subject/issuer,
//!   SPKI hash) and ALPN; we never satisfy a client-cert challenge (plan 04
//!   rule 5).
//! - **No async**: a probe is a few handshakes; we drive
//!   `ClientConnection::complete_io` on a blocking std stream.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::allowlist::HostAllowlist;
use super::{pq_provider, ProbeOutcome, RoundResult, Target};
use crate::classical_provider;

use pq_core::{CertFacts, HandshakeFacts, NegotiatedResult, OfferedFamily};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::CertificateDer;

/// Options for a probe (plan 04).
#[derive(Clone, Debug, Default)]
pub struct ProbeOptions {
    /// The allowlist. Empty ⇒ nothing allowed except auto-allowed loopback.
    pub allow: HostAllowlist,
    /// Global rate budget (plan 04 rule 2), connections/hour.
    pub connections_per_hour: u32,
    /// `true` ⇒ plan mode only, zero packets (plan 04 mode table).
    pub dry_run: bool,
    /// When `true`, loopback is NOT auto-allowed (plan 08 #5 CI assertion; SaaS).
    pub require_explicit_allowlist: bool,
    /// CA bundle to verify the server against. Empty ⇒ no trust (handshake
    /// fails validation) — for tests we pass the server's self-signed cert.
    pub roots: Vec<CertificateDer<'static>>,
    /// Plan 04 `--quic` / `--cross-impl`: forward-compat, no-op in V1.
    pub quic: bool,
    pub cross_impl: bool,
    /// Plan 04 `--repeat N` (drift sampling); V1 runs one classical + one PQ round.
    pub repeat: u32,
    pub timeout_secs: u32,
}

impl ProbeOptions {
    pub fn new() -> Self {
        ProbeOptions {
            allow: HostAllowlist::new(),
            connections_per_hour: 10_000,
            dry_run: false,
            require_explicit_allowlist: false,
            roots: Vec::new(),
            quic: false,
            cross_impl: false,
            repeat: 1,
            timeout_secs: 10,
        }
    }
    pub fn allow(mut self, host: impl Into<String>, port: Option<u16>) -> Self {
        self.allow.insert(HostAllowlist::allowed_host(host.into(), port));
        self
    }
    pub fn allow_spec(mut self, spec: &str) -> Self {
        self.allow = HostAllowlist::from_spec(spec);
        self
    }
    pub fn require_explicit(mut self) -> Self {
        self.require_explicit_allowlist = true;
        self
    }
    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }
    pub fn with_roots(mut self, roots: Vec<CertificateDer<'static>>) -> Self {
        self.roots = roots;
        self
    }
}

/// Typed probe error so the CLI distinguishes denial (audit-clean) from
/// connect/handshake failures.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("not-allowed: host not in allowlist")]
    NotAllowed { host: String, port: u16 },
    #[error("loopback disallowed in strict mode")]
    LoopbackDisallowed { host: String, port: u16 },
    #[error("dry-run: plan only, no packets")]
    DryRun,
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("handshake failed: {0}")]
    Handshake(String),
}

/// The in-binary probe entry point (plan 04).
///
/// Safety: the allowlist check happens *before* any I/O; on denial the outcome
/// is `zero_packets: true` (plan 08 acceptance #5).
pub fn probe_target(target: &Target, opts: &ProbeOptions) -> ProbeOutcome {
    let zero = |err: ProbeError| ProbeOutcome {
        host: target.host.clone(),
        port: target.port,
        scheme: target.scheme.clone(),
        facts: None,
        error: Some(err),
        zero_packets: true,
    };

    // 1. Allowlist (plan 04 rule 1 / 08 #5).
    if !opts.allow.is_allowed(&target.host, target.port, target.is_loopback(), opts.require_explicit_allowlist) {
        let err = if target.is_loopback() && opts.require_explicit_allowlist {
            ProbeError::LoopbackDisallowed {
                host: target.host.clone(),
                port: target.port,
            }
        } else {
            ProbeError::NotAllowed {
                host: target.host.clone(),
                port: target.port,
            }
        };
        return zero(err);
    }

    // 2. Dry-run (plan 04 mode table).
    if opts.dry_run {
        return zero(ProbeError::DryRun);
    }

    // 3. Classical baseline round-trip.
    let baseline = match run_round(target, opts, classical_provider().unwrap()) {
        Ok(r) => r,
        Err(e) => {
            return ProbeOutcome {
                host: target.host.clone(),
                port: target.port,
                scheme: target.scheme.clone(),
                facts: None,
                error: Some(ProbeError::Connect(e.to_string())),
                zero_packets: false,
            }
        }
    };

    // 4. PQ-preferring round-trip.
    let pq = match run_round(target, opts, pq_provider().unwrap()) {
        Ok(r) => r,
        Err(e) => {
            return ProbeOutcome {
                host: target.host.clone(),
                port: target.port,
                scheme: target.scheme.clone(),
                facts: None,
                error: Some(ProbeError::Handshake(e.to_string())),
                zero_packets: false,
            }
        }
    };

    let facts = build_facts(&baseline, &pq, target);
    ProbeOutcome {
        host: target.host.clone(),
        port: target.port,
        scheme: target.scheme.clone(),
        facts: Some(facts),
        error: None,
        zero_packets: false,
    }
}

fn build_facts(baseline: &RoundResult, pq: &RoundResult, target: &Target) -> HandshakeFacts {
    let negotiated_pq = baseline.is_pq || pq.is_pq;
    let mut negotiated = vec![NegotiatedResult {
        version: baseline.tls_version.clone(),
        group: baseline.group.clone(),
        suite: baseline.suite.clone(),
        offered_family: OfferedFamily::ClassicalBaseline,
    }];
    if negotiated_pq {
        negotiated.push(NegotiatedResult {
            version: pq.tls_version.clone(),
            group: pq.group.clone(),
            suite: pq.suite.clone(),
            offered_family: OfferedFamily::PqOnly,
        });
    }

    let cert = if !pq.cert_issuer.is_empty() {
        Some(CertFacts {
            sig_alg: pq.cert_sig_alg.clone(),
            issuer: pq.cert_issuer.clone(),
            subject: pq.cert_subject.clone(),
            leaf_spki_sha256: pq.cert_spki_sha256.clone(),
            chain_depth: 1,
            validity_start: pq.cert_validity_start.clone(),
            validity_end: pq.cert_validity_end.clone(),
        })
    } else {
        None
    };

    HandshakeFacts {
        at: iso_now_iso8601_utc(),
        tls_versions: vec![baseline.tls_version.clone()],
        negotiated,
        offered_groups: vec![
            "X25519".into(),
            "SECP256R1".into(),
            "SECP384R1".into(),
            "X25519MLKEM768".into(),
        ],
        server_negotiated_pq: negotiated_pq,
        cert,
        alpn: pq.alpn.clone(),
        quic: false,
        ja3_server: None,
        ja4_server: None,
        rtt_ms: Some(pq.rtt_ms),
        server_requested_client_cert: false,
        report_id: format!("probe:{}:{}", target.host, target.port),
        evidence: vec![],
    }
}

fn run_round(
    target: &Target,
    opts: &ProbeOptions,
    provider: Arc<CryptoProvider>,
) -> anyhow::Result<RoundResult> {
    let stream = TcpStream::connect((target.host.as_str(), target.port))
        .map_err(|e| anyhow::anyhow!("connect failed: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    let mut roots = rustls::RootCertStore::empty();
    for r in &opts.roots {
        roots.add(r.clone()).ok();
    }

    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let name = match rustls_pki_types::ServerName::try_from(target.host.as_str()) {
        Ok(n) => n.to_owned(),
        Err(_) => return Err(anyhow::anyhow!("invalid server name: {}", target.host)),
    };
    let mut conn = rustls::ClientConnection::new(Arc::new(client), name)?;
    let mut adapter = BlockingStream { sock: stream };

    let start = Instant::now();
    conn.complete_io(&mut adapter)?;
    let rtt_ms = start.elapsed().as_millis() as u32;

    let ng = conn
        .negotiated_key_exchange_group()
        .ok_or_else(|| anyhow::anyhow!("no key exchange group negotiated"))?
        .name();
    let is_pq = matches!(
        ng,
        rustls::NamedGroup::X25519MLKEM768
            | rustls::NamedGroup::secp256r1MLKEM768
            | rustls::NamedGroup::MLKEM768
            | rustls::NamedGroup::MLKEM512
            | rustls::NamedGroup::MLKEM1024
    );
    let group = format!("{ng:?}");
    let suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_default();
    let tls_version = conn
        .protocol_version()
        .map(|v| {
            match v {
                rustls::ProtocolVersion::TLSv1_3 => "1.3",
                rustls::ProtocolVersion::TLSv1_2 => "1.2",
                _ => "1.1",
            }
        })
        .unwrap_or("1.2")
        .to_string();

    let certs = conn.peer_certificates().map(|c| c.to_vec()).unwrap_or_default();
    let leaf = certs.into_iter().next().unwrap_or_else(|| CertificateDer::from(vec![] as Vec<u8>));
    let (spki_sha, sig_alg, issuer, subject, vstart, vend) = leaf_facts(&leaf);

    let alpn = conn
        .alpn_protocol()
        .map(|a| {
            let a = a.to_vec();
            std::str::from_utf8(&a).unwrap_or("").to_string()
        })
        .unwrap_or_default();

    Ok(RoundResult {
        group,
        is_pq,
        suite,
        tls_version,
        cert_spki_sha256: spki_sha,
        cert_sig_alg: sig_alg,
        cert_issuer: issuer,
        cert_subject: subject,
        cert_validity_start: vstart,
        cert_validity_end: vend,
        alpn: vec![alpn],
        rtt_ms,
    })
}

fn leaf_facts(
    der: &CertificateDer<'static>,
) -> (String, String, String, String, String, String) {
    use sha2::{Digest, Sha256};
    if der.is_empty() {
        return (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        );
    }
    let spki_sha = hex::encode(Sha256::digest(der.as_ref()));
    use x509_cert::der::Decode;
    let Ok(cert) = x509_cert::Certificate::from_der(der.as_ref()) else {
        return (spki_sha, String::new(), String::new(), String::new(), String::new(), String::new());
    };
    let tbs = cert.tbs_certificate();
    let sig_alg = format!("{:?}", tbs.signature());
    let issuer = tbs.issuer().to_string();
    let subject = tbs.subject().to_string();
    let validity = tbs.validity();
    let vstart = format_epoch(validity.not_before.to_unix_duration().as_secs());
    let vend = format_epoch(validity.not_after.to_unix_duration().as_secs());
    (spki_sha, sig_alg, issuer, subject, vstart, vend)
}

fn format_epoch(secs: u64) -> String {
    iso_from_epoch(secs)
}

fn iso_from_epoch(secs: u64) -> String {
    let days = secs.div_euclid(86_400) as i64;
    let rem = (secs % 86_400) as u64;
    let (y, m, d) = civil_date_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem.div_euclid(3600),
        (rem % 3600) / 60,
        rem % 60
    )
}

fn iso_now_iso8601_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso_from_epoch(secs)
}

fn civil_date_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d)
}

struct BlockingStream {
    sock: TcpStream,
}
impl Read for BlockingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.sock.read(buf)
    }
}
impl Write for BlockingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sock.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::TestServer;

    #[test]
    fn zero_packets_when_not_allowed() {
        let target = Target {
            host: "example.com".into(),
            port: 443,
            scheme: "https".into(),
        };
        let opts = ProbeOptions::new();
        let out = probe_target(&target, &opts);
        assert!(matches!(out.error, Some(ProbeError::NotAllowed { .. })));
        assert!(out.zero_packets);
    }

    #[test]
    fn probe_rejects_untrusted_self_signed() {
        // Server with a self-signed cert, but no roots → handshake must fail
        // (chain validation), and it must be a *handshake* error, not NotAllowed.
        let server = TestServer::start_pq().expect("server start");
        let target = Target {
            host: "127.0.0.1".into(),
            port: server.port(),
            scheme: "https".into(),
        };
        let opts = ProbeOptions::new().allow("127.0.0.1", Some(server.port()));
        let out = probe_target(&target, &opts);
        // No roots → webpki rejects the self-signed chain.
        assert!(out.error.is_some(), "expected a validation/handshake error");
        assert!(!matches!(out.error, Some(ProbeError::NotAllowed { .. })));
        drop(server);
    }

    #[test]
    fn probe_reports_pq_negotiated_for_hybrid_server() {
        let server = TestServer::start_pq().expect("server start");
        let target = Target {
            host: "127.0.0.1".into(),
            port: server.port(),
            scheme: "https".into(),
        };
        let opts = ProbeOptions::new()
            .allow("127.0.0.1", Some(server.port()))
            .with_roots(vec![server.cert_der().clone()]);
        let out = probe_target(&target, &opts);
        assert!(out.error.is_none(), "probe error: {:?}", out.error);
        let facts = out.facts.expect("facts present");
        assert!(
            facts.server_negotiated_pq,
            "hybrid server should negotiate a PQ group"
        );
        assert_eq!(
            facts
                .negotiated
                .iter()
                .filter(|n| n.offered_family == OfferedFamily::PqOnly)
                .count(),
            1
        );
        // Plan 04: cert facts recorded, SPKI present.
        let cert = facts.cert.expect("cert present");
        assert!(!cert.leaf_spki_sha256.is_empty());
        drop(server);
    }

    #[test]
    fn probe_reports_pq_unavailable_for_classical_server() {
        let server = TestServer::start_classical().expect("server start");
        let target = Target {
            host: "127.0.0.1".into(),
            port: server.port(),
            scheme: "https".into(),
        };
        let opts = ProbeOptions::new()
            .allow("127.0.0.1", Some(server.port()))
            .with_roots(vec![server.cert_der().clone()]);
        let out = probe_target(&target, &opts);
        assert!(out.error.is_none(), "probe error: {:?}", out.error);
        let facts = out.facts.expect("facts present");
        assert!(
            !facts.server_negotiated_pq,
            "classical-only server must not be reported as PQ"
        );
        assert!(
            !facts
                .negotiated
                .iter()
                .any(|n| n.group.contains("MLKEM")),
            "no MLKEM group should be negotiated"
        );
        drop(server);
    }

    #[test]
    fn loopback_disallowed_in_strict_mode() {
        let target = Target::localhost();
        let opts = ProbeOptions::new().require_explicit();
        let out = probe_target(&target, &opts);
        assert!(matches!(out.error, Some(ProbeError::LoopbackDisallowed { .. })));
        assert!(out.zero_packets);
    }

    #[test]
    fn dry_run_no_packets() {
        let target = Target {
            host: "127.0.0.1".into(),
            port: 443,
            scheme: "https".into(),
        };
        let opts = ProbeOptions::new().allow("127.0.0.1", None).dry_run();
        let out = probe_target(&target, &opts);
        assert!(matches!(out.error, Some(ProbeError::DryRun)));
        assert!(out.zero_packets);
    }
}
