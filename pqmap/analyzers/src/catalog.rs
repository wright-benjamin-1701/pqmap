//! Framework API catalog (plan 02): data, not code.
//!
//! Rows are loaded from an embedded TOML table. Every row has:
//!   - `lang`            : which language the match applies to
//!   - `kind`            : `client` | `server` | `tls-config` | `crypto`
//!   - `pattern`         : regex (matched against source lines)
//!   - `tls_owner_hint`  : a hint of the TLS owner (`runtime`, `library`, …)
//!   - `framework`       : the framework name (for edge `framework` field)
//!   - `api_name`        : stable rule id for SARIF / evidence (plan 07)
//!   - `confidence`      : base confidence for a matched row
//!
//! Adding a framework = adding rows.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use regex::RegexSet;

use crate::Lang;

/// What a row captures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryKind {
    Client,
    Server,
    TlsConfig,
    Crypto,
}

/// One catalog row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub lang: Lang,
    pub kind: EntryKind,
    /// Rust regex (Rust `regex` crate).
    pub pattern: String,
    /// Human-friendly API name (rule id / evidence).
    pub api_name: String,
    /// Framework name (populates the edge's `framework`).
    pub framework: String,
    /// Hint of the TLS owner (populates `tls_provider` if still None).
    pub tls_owner_hint: Option<TlsOwnerHint>,
    /// Base confidence for a successful match (0..1).
    #[serde(default = "default_conf")]
    pub confidence: f32,
    /// Optional protocol hint.
    pub protocol: Option<String>,
}

fn default_conf() -> f32 {
    0.6
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TlsOwnerHint {
    Runtime,
    Library,
    Os,
    CodeInline,
    Infra,
}

/// A set of rows grouped by language.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    /// Compiled patterns cache, keyed by (lang, kind).
    patterns: HashMap<(Lang, EntryKind), Vec<(Row, regex::Regex)>>,
    /// RegexSet for fast multi-pattern matching, keyed by (lang, kind).
    /// Indices correspond to the `patterns` vec for the same key.
    regex_sets: HashMap<(Lang, EntryKind), RegexSet>,
}

impl Catalog {
    /// Build an embedded catalog from TOML.
    pub fn built_in() -> Result<Catalog, Box<dyn std::error::Error>> {
        let s = include_str!("embedded_catalog.toml");
        #[derive(Deserialize)]
        struct Doc {
            row: Vec<Row>,
        }
        let d: Doc = toml::from_str(s)?;
        Ok(Self::from_rows(d.row))
    }

    /// Build from a vector of rows (test / custom).
    pub fn from_rows(rows: Vec<Row>) -> Catalog {
        let mut patterns: HashMap<(Lang, EntryKind), Vec<(Row, regex::Regex)>> =
            HashMap::new();
        for r in &rows {
            if let Ok(re) = regex::Regex::new(&r.pattern) {
                patterns
                    .entry((r.lang, r.kind))
                    .or_default()
                    .push((r.clone(), re));
            }
        }
        // Build RegexSets for each (lang, kind) group: single-pass matching.
        let mut regex_sets: HashMap<(Lang, EntryKind), RegexSet> = HashMap::new();
        for (key, entries) in &patterns {
            let pats: Vec<&str> = entries.iter().map(|(r, _)| r.pattern.as_str()).collect();
            if let Ok(set) = RegexSet::new(&pats) {
                regex_sets.insert(*key, set);
            }
        }
        Catalog { patterns, regex_sets }
    }

    /// Iterate rows of a kind for a language, with compiled regex.
    pub fn rows_for<'a>(
        &'a self,
        lang: Lang,
        kind: EntryKind,
    ) -> impl Iterator<Item = &'a (Row, regex::Regex)> {
        self.patterns
            .get(&(lang, kind))
            .map(|v| v.iter())
            .unwrap_or_else(|| [].iter())
    }

    /// Return indices of rows that match `line` for `(lang, kind)` using the
    /// RegexSet (single DFA pass). Falls back to per-row matching if no set.
    pub fn matching_indices(
        &self,
        lang: Lang,
        kind: EntryKind,
        line: &str,
    ) -> Vec<usize> {
        if let Some(set) = self.regex_sets.get(&(lang, kind)) {
            set.matches(line).into_iter().collect()
        } else {
            // Fallback: test each individually
            self.patterns
                .get(&(lang, kind))
                .map(|entries| {
                    entries
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, re))| re.is_match(line))
                        .map(|(i, _)| i)
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    /// Get a specific row + regex by index for a (lang, kind) group.
    pub fn row_at(&self, lang: Lang, kind: EntryKind, idx: usize) -> Option<&(Row, regex::Regex)> {
        self.patterns.get(&(lang, kind)).and_then(|v| v.get(idx))
    }

    pub fn is_client(&self, lang: Lang) -> bool {
        self.patterns.contains_key(&(lang, EntryKind::Client))
    }
    pub fn is_server(&self, lang: Lang) -> bool {
        self.patterns.contains_key(&(lang, EntryKind::Server))
    }
    pub fn is_tls_config(&self, lang: Lang) -> bool {
        self.patterns.contains_key(&(lang, EntryKind::TlsConfig))
    }
    pub fn is_crypto(&self, lang: Lang) -> bool {
        self.patterns.contains_key(&(lang, EntryKind::Crypto))
    }

    /// Total number of rows.
    pub fn len(&self) -> usize {
        self.patterns.values().map(|v| v.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_loads_without_error() {
        let c = Catalog::built_in().unwrap();
        assert!(c.len() > 30, "catalog should have >30 rows, got {}", c.len());
    }

    #[test]
    fn rows_for_filters_correctly() {
        let c = Catalog::built_in().unwrap();
        let js_clients: Vec<_> = c.rows_for(Lang::Js, EntryKind::Client).collect();
        assert!(!js_clients.is_empty(), "JS should have client rows");
        for (row, _) in &js_clients {
            assert_eq!(row.lang, Lang::Js);
            assert_eq!(row.kind, EntryKind::Client);
        }
    }

    #[test]
    fn empty_catalog_from_empty_rows() {
        let c = Catalog::from_rows(vec![]);
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn has_java_and_go_rows() {
        let c = Catalog::built_in().unwrap();
        assert!(c.is_client(Lang::Java), "Java should have client rows");
        assert!(c.is_server(Lang::Java), "Java should have server rows");
        assert!(c.is_client(Lang::Go), "Go should have client rows");
        assert!(c.is_server(Lang::Go), "Go should have server rows");
    }
}
