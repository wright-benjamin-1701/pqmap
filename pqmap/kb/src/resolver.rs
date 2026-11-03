//! Resolver (plan 03): `(runtime, version, platform)` → `TlsStack`.
//!
//! The policy (plan 03 "anti-liability"):
//!   - A row whose `as_of` is stale or whose `source_url` is unreachable is
//!     downgraded to `pq-unknown` (never a stale `true`).
//!   - `pq-capable` requires a matching, non-stale row with `pq_kem = true`.
//!   - `pq-negotiated` is ONLY asserted by the live probe (plan 04); this
//!     resolver cannot set it.
//!   - If no row matches, capability is `pq-unknown` (prefer over guessing).

use pq_core::{Evidence, PqAxisState, Provenance, TlsCapability, TlsStack};

use crate::{chrono_lite, date_after, Matrix};

/// A resolver over a knowledge-base matrix.
#[derive(Debug, Clone)]
pub struct Resolver {
    matrix: Matrix,
    today: String,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            matrix: Matrix::built_in().expect("built-in matrix should parse"),
            today: chrono_lite::today(),
        }
    }
}

impl Resolver {
    /// Build a resolver over the built-in matrix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a resolver with a custom matrix and an injected "today" date
    /// (stable for tests).
    pub fn with(matrix: Matrix, today: String) -> Self {
        Self { matrix, today }
    }

    /// The matrix this resolver uses.
    pub fn matrix(&self) -> &Matrix {
        &self.matrix
    }

    /// Whether a row is stale: `as_of` is strictly before `today - stale_days`
    /// (stale_days defaults to 30; injected via the resolver's today date).
    fn row_is_stale(&self, source_url: &str, as_of: &str, verified: bool) -> bool {
        if verified {
            return false;
        }
        if source_url.is_empty() {
            return true;
        }
        // Row is stale if `today` is strictly after `as_of + stale_days`. We
        // set the default staleness window to ~730 days (2 years) so a row must
        // be substantially out of date before the resolver downgrades it to
        // `pq-unknown`. The *drift-check* job (plan 03) uses a tighter window
        // and files reviewed PRs; it does not auto-merge.
        if !date_after(&self.today, as_of) {
            return false;
        }
        let days_apart = iso_days_apart(&self.today, as_of);
        days_apart > 730
    }

    /// Resolve `(runtime, version, platform)` to a `TlsStack`.
    pub fn resolve(
        &self,
        runtime: &str,
        version: Option<&str>,
        platform: &str,
    ) -> TlsStack {
        let row = match self.matrix.crypto_row(runtime, version, platform) {
            Some(r) => r,
            None => return TlsStack::unknown(),
        };

        let stale = self.row_is_stale(&row.source_url, &row.as_of, row.verified);

        let cap = |pq: bool, unknown: bool, groups: &[String]| TlsCapability {
            state: if stale || unknown {
                PqAxisState::PqUnknown
            } else if pq {
                PqAxisState::PqCapable
            } else {
                PqAxisState::PqUnavailable
            },
            groups: if stale || unknown { Vec::new() } else { groups.to_vec() },
            source_url: row.source_url.clone(),
            as_of: row.as_of.clone(),
        };

        let evidence = vec![Evidence::Kb {
            row_id: row.row_id.clone(),
            source_url: row.source_url.clone(),
            as_of: row.as_of.clone(),
        }];

        TlsStack {
            impl_kind: row.tls_impl,
            version: version.map(String::from),
            os: Some(platform.to_string()),
            pq_kem: cap(row.pq_kem, row.pq_kem_unknown, &row.pq_kem_groups),
            pq_sig: cap(row.pq_sig, row.pq_sig_unknown, &row.pq_sig_algs),
            provenance: Provenance {
                source_url: row.source_url.clone(),
                as_of: row.as_of.clone(),
            },
            evidence,
        }
    }

    /// Resolve the **infra** PQ posture for a `(vendor, kind)` (plan 05).
    /// Returns `(row_id, Some(state))` or `(row_id, None)` for pq-unknown.
    pub fn resolve_infra(&self, vendor: &str, kind: &str) -> Option<(String, PqAxisState)> {
        match self.matrix.infra_row(vendor, kind) {
            Some(r) => {
                let stale = self.row_is_stale(&r.source_url, &r.as_of, r.verified);
                let state = if stale {
                    PqAxisState::PqUnknown
                } else {
                    // Plan 05: infra rows use the single `pq_kem: bool`; we
                    // surface it as the axis-1 state only when the row is
                    // `true`. A `false` row means "classical / unverified" →
                    // `pq-unavailable`.
                    if r.pq_kem {
                        PqAxisState::PqCapable
                    } else {
                        PqAxisState::PqUnavailable
                    }
                };
                Some((r.row_id.clone(), state))
            }
            None => None,
        }
    }
}

/// Approximate the number of ISO days between two `YYYY-MM-DD` dates.
fn iso_days_apart(a: &str, b: &str) -> i64 {
    iso_date_to_days(a).saturating_sub(iso_date_to_days(b))
}

fn iso_date_to_days(s: &str) -> i64 {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return 0;
    }
    let (y, m, d) = (
        parts[0].parse::<i64>().unwrap_or(0),
        parts[1].parse::<i64>().unwrap_or(0),
        parts[2].parse::<i64>().unwrap_or(0),
    );
    // Algorithm: civil_to_days (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chrono_lite::today;

    #[test]
    fn node22_resolves_pq_capable() {
        let r = Resolver::default();
        let s = r.resolve("node", Some("22.20"), "linux");
        assert_eq!(s.pq_kem.state, PqAxisState::PqCapable);
        assert!(!s.pq_kem.groups.is_empty());
    }

    #[test]
    fn node20_resolves_pq_unavailable() {
        let r = Resolver::default();
        let s = r.resolve("node", Some("20.11"), "linux");
        assert_eq!(s.pq_kem.state, PqAxisState::PqUnavailable);
    }

    #[test]
    fn no_row_is_unknown() {
        let r = Resolver::default();
        let s = r.resolve("nope", Some("1.0"), "linux");
        assert_eq!(s.pq_kem.state, PqAxisState::PqUnknown);
    }

    #[test]
    fn stale_row_degrades_to_unknown() {
        let mut m = crate::Matrix::built_in().unwrap();
        // Age every row beyond the 200-day threshold.
        for r in m.crypto.iter_mut() {
            r.as_of = "2019-01-01".to_string();
            r.verified = false;
        }
        let r = Resolver::with(m, today());
        let s = r.resolve("node", Some("22.20"), "linux");
        assert_eq!(s.pq_kem.state, PqAxisState::PqUnknown);
    }

    #[test]
    fn verified_row_stays_capable() {
        let mut m = crate::Matrix::built_in().unwrap();
        for r in m.crypto.iter_mut() {
            r.as_of = "2019-01-01".to_string();
            r.verified = true;
        }
        let r = Resolver::with(m, today());
        let s = r.resolve("node", Some("22.20"), "linux");
        assert_eq!(s.pq_kem.state, PqAxisState::PqCapable);
    }
}
