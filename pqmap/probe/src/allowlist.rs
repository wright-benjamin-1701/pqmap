//! Consent / allowlist enforcement (plan 04 safety rules 1 & 7).
//!
//! Loopback is auto-allowed in non-strict mode (local development scan
//! carve-out, plan 04 rule 1). RFC 1918 / link-local are NOT auto-allowed
//! (plan 04 rule 4: "unless explicit").

use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AllowedHost {
    pub host: String,
    pub port: Option<u16>,
}

impl AllowedHost {
    pub fn new(host: impl Into<String>, port: Option<u16>) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl fmt::Display for AllowedHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(p) => write!(f, "{}:{}", self.host, p),
            None => write!(f, "{}", self.host),
        }
    }
}

/// The set of explicitly-allowed `(host, port)` pairs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostAllowlist {
    entries: BTreeSet<AllowedHost>,
}

impl HostAllowlist {
    pub fn new() -> Self {
        Self::default()
    }
    /// Parse a `--allow-hosts host[,host:port,...]` spec.
    pub fn from_spec(spec: &str) -> Self {
        let mut a = Self::default();
        for part in spec.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            let (host, port) = match p.rsplit_once(':') {
                Some((h, p)) if p.parse::<u16>().is_ok() => {
                    (h.to_string(), Some(p.parse::<u16>().unwrap()))
                }
                None => (p.to_string(), None),
                _ => (p.to_string(), None),
            };
            a.insert(AllowedHost::new(host, port));
        }
        a
    }
    pub fn insert(&mut self, h: AllowedHost) {
        self.entries.insert(h);
    }
    pub fn contains(&self, h: &AllowedHost) -> bool {
        self.entries.contains(h)
    }
    pub fn allowed_host(host: String, port: Option<u16>) -> AllowedHost {
        AllowedHost::new(host, port)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &AllowedHost> {
        self.entries.iter()
    }
    /// Is `host:port` permitted? Loopback passes (unless `strict`), per plan 04.
    pub fn is_allowed(
        &self,
        host: &str,
        port: u16,
        target_is_loopback: bool,
        strict: bool,
    ) -> bool {
        if target_is_loopback && !strict {
            return true;
        }
        self.entries.iter().any(|e| {
            e.host.eq_ignore_ascii_case(host)
                && e.port.map(|p| p == port).unwrap_or(true)
        })
    }
}
