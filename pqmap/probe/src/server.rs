//! A minimal TLS 1.3 test server (rustls + rcgen) for offline probe tests.
//!
//! Plan 04 requires a "wiremock-style TLS test server with configurable group
//! set so unit tests can assert probe output without touching the real
//! internet." We provide two flavours:
//!
//! - `start_classical()` — group order `[X25519, P-256, P-384]` (no PQ).
//! - `start_pq()` — group order `[X25519MLKEM768, X25519, P-256, P-384]`.
//!
//! Both bind to `127.0.0.1:0` (ephemeral loopback), serve the same
//! self-signed cert, and stay alive until dropped. A probe test asserts
//! `server_negotiated_pq` accordingly (plan 08 acceptance #2).
//!
//! Implementation notes:
//!
//! - We spawn an accept thread that owns the `TcpListener`. On `Drop`, we drop
//!   the server, which drops our strong reference to the listener *only* if
//!   the accept thread has already released it. In practice the accept call
//!   holds it; we rely on the thread dying when the socket is closed
//!   (OS closes the fd for us, `accept` returns an error). The thread is
//!   detached — for in-process tests this is fine; the OS reclaims the fd
//!   when the process exits.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use rustls_pki_types::CertificateDer;

/// One TLS 1.3 server on a loopback ephemeral port.
pub struct TestServer {
    thread: Option<JoinHandle<()>>,
    port: u16,
    cert: CertificateDer<'static>,
    group_order: Vec<String>,
}

impl TestServer {
    pub fn port(&self) -> u16 {
        self.port
    }
    /// The self-signed cert DER (tests pass this to `ProbeOptions::roots`).
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert
    }
    /// The offering group order of this server (human-readable).
    pub fn group_order(&self) -> Vec<String> {
        self.group_order.clone()
    }

    /// A classical-only (no PQ) test server.
    pub fn start_classical() -> anyhow::Result<Self> {
        Self::start_with(vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ])
    }

    /// A hybrid-PQ (X25519MLKEM768 preferred) test server.
    pub fn start_pq() -> anyhow::Result<Self> {
        Self::start_with(vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ])
    }

    fn start_with(
        groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    ) -> anyhow::Result<Self> {
        let ck = rcgen::generate_simple_self_signed(vec![
            "127.0.0.1".into(),
            "localhost".into(),
        ])
        .map_err(|e| anyhow::anyhow!("self-signed cert failed: {e}"))?;
        let cert = CertificateDer::from(ck.cert);
        let key = ck.signing_key.serialize_der();

        let key_pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(key);
        let mut prov = rustls::crypto::aws_lc_rs::default_provider();
        prov.kx_groups = groups.iter().copied().collect();

        let mut srv = rustls::ServerConfig::builder_with_provider(Arc::new(prov))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(key_pkcs8),
            )?;
        srv.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(srv);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let group_names: Vec<String> = groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();

        let cfg = config.clone();
        let thread = thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((sock, _)) => {
                        let cfg = cfg.clone();
                        thread::spawn(move || {
                            let mut io = match rustls::ServerConnection::new(cfg) {
                                Ok(c) => c,
                                Err(_) => return,
                            };
                            let mut adapter = BlockingStream { sock };
                            if io.complete_io(&mut adapter).is_err() {
                                return;
                            }
                            // Keep the socket open briefly so the client can
                            // read the peer cert before the handler finishes.
                            thread::sleep(std::time::Duration::from_millis(200));
                        });
                    }
                    Err(ref e) if is_listener_closed(e) => break,
                    Err(_) => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
            }
        });

        Ok(TestServer {
            thread: Some(thread),
            port,
            cert,
            group_order: group_names,
        })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // The listener is owned by the accept thread. Dropping this struct
        // releases our handle on it; the OS closes the fd and the accept call
        // sees an error. The detached accept thread exits on the next loop
        // iteration. Tests don't join it (avoids deadlocks); the OS reclaims
        // the fd on process exit, and the leaked thread is short-lived.
        if let Some(h) = self.thread.take() {
            std::mem::forget(h);
        }
        let _ = self.group_order;
    }
}

/// Heuristic: the accept socket was closed (not just "no pending connection").
fn is_listener_closed(e: &std::io::Error) -> bool {
    // Closed fd on Unix → EBADF (98 on Linux, 54 on macOS).
    let kind = e.kind();
    matches!(
        kind,
        std::io::ErrorKind::Other
    ) && e.raw_os_error()
        .map(|c| c == 98 || c == 54)
        .unwrap_or(false)
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

    #[test]
    fn start_and_read_metadata() {
        let s = TestServer::start_pq().expect("pq server");
        assert!(s.port() != 0);
        assert!(!s.cert_der().as_ref().is_empty());
        assert!(
            s.group_order().iter().any(|g| g.contains("X25519MLKEM768")),
            "pq server should offer X25519MLKEM768: got {:?}",
            s.group_order()
        );
        drop(s);

        let s2 = TestServer::start_classical().expect("classical server");
        assert!(
            !s2.group_order().iter().any(|g| g.contains("MLKEM")),
            "classical server must not offer MLKEM: got {:?}",
            s2.group_order()
        );
        drop(s2);
    }
}
