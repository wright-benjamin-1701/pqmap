//! The matrix data + loader (plan 03).
//!
//! The matrix is **data, not code**: adding a framework = adding rows. It is
//! embedded (`embedded_matrix.toml`) as the built-in default, but may be
//! overridden at runtime via the `PQMAP_KB` env var or `Matrix::load_file()`
//! (this is the hook for the monthly drift-check job, plan 03).

use std::path::Path;

use serde::Deserialize;
use pq_core::{InfraKbRow, KbRow};

/// The full curated matrix, deserialized from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct Matrix {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crypto: Vec<KbRow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub infra: Vec<InfraKbRow>,
}

/// A minimal ISO-8601 date helper (YYYY-MM-DD) to avoid a chrono dependency.
pub mod chrono_lite {
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Today's UTC date as `YYYY-MM-DD`.
    pub fn today() -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        days_to_date(secs.div_euclid(86_400))
    }

    fn days_to_date(days: i64) -> String {
        // Days -> (year, month, day) using the civil-from-days algorithm
        // (Howard Hinnant's `civil_from_days`).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{:04}-{:02}-{:02}", y, m, d)
    }
}

/// Compare two ISO dates (YYYY-MM-DD). Returns `true` if `a` is strictly after
/// `b`. Used to detect a stale row (plan 03 drift-check).
pub fn date_after(a: &str, b: &str) -> bool {
    a > b
}

impl Matrix {
    /// Build the built-in matrix (embedded TOML). Cached after first parse.
    pub fn built_in() -> Result<Matrix, toml::de::Error> {
        use std::sync::OnceLock;
        static CACHED: OnceLock<Matrix> = OnceLock::new();
        let m = CACHED.get_or_init(|| {
            let s = include_str!("embedded_matrix.toml");
            toml::from_str::<Matrix>(s).expect("built-in matrix should parse")
        });
        Ok(m.clone())
    }

    /// Load from a file (drift-check override / tenant matrix).
    pub fn load_file(path: impl AsRef<Path>) -> Result<Matrix, Box<dyn std::error::Error>> {
        let s = std::fs::read_to_string(path)?;
        let m: Matrix = toml::from_str(&s)?;
        Ok(m)
    }

    /// Find the best-fitting crypto row for `(runtime, version, platform)`.
    ///
    /// "Best": the row with the largest `version_min` that is ≤ the target
    /// version, matching the platform exactly or `any`. Returns `None` if no
    /// row matches (caller resolves to `pq-unknown`).
    ///
    /// Version compare: numeric if both parse, otherwise lexical (best effort
    /// — versions in the KB are dot-separated numerics).
    pub fn crypto_row(
        &self,
        runtime: &str,
        version: Option<&str>,
        platform: &str,
    ) -> Option<&KbRow> {
        let platform = platform.to_lowercase();
        let mut best: Option<(&KbRow, f64)> = None;
        for row in &self.crypto {
            if !row.runtime.eq_ignore_ascii_case(runtime) {
                continue;
            }
            // Platform: exact match or `any`.
            let plat = row.platform.to_lowercase();
            if plat != platform && plat != "any" {
                continue;
            }
            // Version: the target must be >= row.version_min (semantic compare).
            let version_ok = match (version, row.version_min.as_deref()) {
                (None, None) => true,
                (None, Some(_)) => false, // target has no version; can't claim.
                (Some(_), None) => true,
                (Some(v), Some(min)) => version_geq(v, min),
            };
            if !version_ok {
                continue;
            }
            // Prefer exact platform over `any`, and larger version_min.
            let plat_score = if plat == platform { 1.0 } else { 0.5 };
            let ver_score = row
                .version_min
                .as_deref()
                .map(|m| f64_version(m))
                .unwrap_or(0.0);
            let score = plat_score * 1000.0 + ver_score;
            let better = match best {
                None => true,
                Some((_, best_score)) => score > best_score,
            };
            if better {
                best = Some((row, score));
            }
        }
        best.map(|(r, _)| r)
    }

    /// Find an infra row by (vendor, kind).
    pub fn infra_row(&self, vendor: &str, kind: &str) -> Option<&InfraKbRow> {
        self.infra.iter().find(|r| {
            r.vendor.eq_ignore_ascii_case(vendor) && r.kind.eq_ignore_ascii_case(kind)
        })
    }
}

/// Numeric version compare: `a >= b`. Falls back to segmentwise lexical.
pub fn version_geq(a: &str, b: &str) -> bool {
    let pa = a.parse::<f64>();
    let pb = b.parse::<f64>();
    match (pa, pb) {
        (Ok(x), Ok(y)) => x >= y,
        _ => {
            // Segmentwise compare.
            let sa: Vec<u64> = a
                .split('.')
                .map(|s| s.parse::<u64>().unwrap_or(0))
                .collect();
            let sb: Vec<u64> = b
                .split('.')
                .map(|s| s.parse::<u64>().unwrap_or(0))
                .collect();
            for i in 0..sa.len().max(sb.len()) {
                let x = sa.get(i).copied().unwrap_or(0);
                let y = sb.get(i).copied().unwrap_or(0);
                if x != y {
                    return x > y;
                }
            }
            true
        }
    }
}

fn f64_version(v: &str) -> f64 {
    // Best-effort: first component is the major.
    v.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_lookup_node22_linux_is_pq() {
        let m = Matrix::built_in().unwrap();
        let row = m.crypto_row("node", Some("22.20.0"), "linux").expect("node22/linux");
        assert!(row.pq_kem, "node 22 / linux should be PQ KEM capable");
        assert!(row
            .pq_kem_groups
            .iter()
            .any(|g| g.contains("MLKEM")));
    }

    #[test]
    fn row_lookup_node20_linux_is_classical() {
        let m = Matrix::built_in().unwrap();
        let row = m.crypto_row("node", Some("20.11.0"), "linux").expect("node20/linux");
        assert!(!row.pq_kem, "node 20 / linux is classical (OpenSSL 3.0)");
    }

    #[test]
    fn row_lookup_unknown_runtime_is_none() {
        let m = Matrix::built_in().unwrap();
        assert!(m.crypto_row("nonexistent", Some("1.0"), "linux").is_none());
    }

    #[test]
    fn row_lookup_jvm21_linux_is_pq() {
        let m = Matrix::built_in().unwrap();
        let row = m.crypto_row("jvm", Some("21"), "linux").expect("jvm21/linux");
        assert!(row.pq_kem, "JVM 21 with BC JSSE on linux should be PQ KEM capable");
        assert_eq!(row.provider, "bouncycastle-jsse");
    }

    #[test]
    fn row_lookup_jvm17_is_classical() {
        let m = Matrix::built_in().unwrap();
        let row = m.crypto_row("jvm", Some("17"), "linux").expect("jvm17/linux");
        assert!(!row.pq_kem, "JVM 17 is classical");
    }

    #[test]
    fn row_lookup_go124_linux_is_pq() {
        let m = Matrix::built_in().unwrap();
        let row = m.crypto_row("go", Some("1.24"), "linux").expect("go1.24/linux");
        assert!(row.pq_kem, "Go 1.24 on linux should be PQ KEM capable");
    }

    #[test]
    fn row_lookup_go122_is_classical() {
        let m = Matrix::built_in().unwrap();
        let row = m.crypto_row("go", Some("1.22"), "linux").expect("go1.22/linux");
        assert!(!row.pq_kem, "Go 1.22 is classical");
    }
}
