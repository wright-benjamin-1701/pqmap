//! Per-file, line-based scanner (plan 02).
//!
//! The scanner walks the *lines* of a file, matches them against the catalog
//! (client / server / tls-config / crypto) and records a `Match` for each hit.
//! A `Match` carries:
//!   - kind              (client / server / tls-config / crypto)
//!   - api_name          (catalog rule id for SARIF / evidence)
//!   - framework         (catalog framework name)
//!   - line              (1-indexed)
//!   - symbol            (best-effort identifier that matched)
//!   - reason            (Literal / Alias / Subclass / Di / Import)
//!   - confidence        (row.confidence + boost by Reason)
//!   - protocol          (catalog row hint)
//!
//! The reason drives a *small* confidence boost (max 0.10) and is recorded in
//! the resolution chain (plan 02 "scope-aware, not global-string matching").

use crate::catalog::{Catalog, EntryKind, TlsOwnerHint};
use crate::symbol::SymbolTable;
use crate::Lang;

/// What sort of match it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Client,
    Server,
    TlsConfig,
    Crypto,
}

impl Kind {
    pub fn entry(&self) -> EntryKind {
        match self {
            Kind::Client => EntryKind::Client,
            Kind::Server => EntryKind::Server,
            Kind::TlsConfig => EntryKind::TlsConfig,
            Kind::Crypto => EntryKind::Crypto,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Kind::Client => "client",
            Kind::Server => "server",
            Kind::TlsConfig => "tls-config",
            Kind::Crypto => "crypto",
        }
    }
}

/// The "why" a match got a confidence boost (plan 02 resolution chain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Literal,
    Alias,
    Subclass,
    Di,
    Import,
}

impl Reason {
    pub fn label(&self) -> &'static str {
        match self {
            Reason::Literal => "literal",
            Reason::Alias => "alias",
            Reason::Subclass => "subclass",
            Reason::Di => "di",
            Reason::Import => "import",
        }
    }
}

/// A single match in a file.
#[derive(Clone, Debug)]
pub struct Match {
    pub kind: Kind,
    pub api_name: String,
    pub framework: String,
    pub line: u32,
    /// The verbatim source line the match was found on. `extract_destination`
    /// and `--explain` consume this to bind the *real* URL literal (the
    /// `symbol` is a best-effort extraction and may contain the URL with
    /// broken delimiters).
    pub line_text: String,
    pub symbol: String,
    pub reason: Reason,
    pub confidence: f32,
    pub protocol: Option<String>,
    /// Hint of the TLS owner (copied from the catalog row).
    pub tls_owner_hint: Option<TlsOwnerHint>,
}

impl Match {
    /// A short human-readable line for the resolution chain (plan 02 `--explain`).
    pub fn explain(&self) -> String {
        format!(
            "[{}] {} at line {} ({}) — confidence {:.2}",
            self.kind.label(),
            self.api_name,
            self.line,
            self.reason.label(),
            self.confidence
        )
    }

    /// The TLS owner hint (copied from the catalog row).
    pub fn tls_owner_hint(&self) -> Option<TlsOwnerHint> {
        self.tls_owner_hint
    }
}

/// Scan a single source file and return all matches. `symbols` carries the
/// per-file symbol table (built by the pipeline) that boosts confidence.
pub fn scan_line(
    line: &str,
    line_no: u32,
    lang: Lang,
    catalog: &Catalog,
    symbols: &SymbolTable,
) -> Vec<Match> {
    let mut out: Vec<Match> = Vec::new();
    // Extract symbol lazily (only when there's at least one hit).
    let mut symbol: Option<String> = None;
    for (kind, entry) in [
        (Kind::Client, EntryKind::Client),
        (Kind::Server, EntryKind::Server),
        (Kind::TlsConfig, EntryKind::TlsConfig),
        (Kind::Crypto, EntryKind::Crypto),
    ] {
        // Single-pass RegexSet match: tests all patterns for this (lang, kind)
        // in one DFA traversal, then only runs classify on the hits.
        let hits = catalog.matching_indices(lang, entry, line);
        for idx in hits {
            let (row, _) = match catalog.row_at(lang, entry, idx) {
                Some(r) => r,
                None => continue,
            };
            let sym = symbol.get_or_insert_with(|| extract_symbol(line));
            let reason = classify_reason(sym, symbols, &row.framework, lang);
            let boost = boost_for(reason);
            let conf = (row.confidence + boost).min(1.0);
            out.push(Match {
                kind,
                api_name: row.api_name.clone(),
                framework: row.framework.clone(),
                line: line_no,
                line_text: line.to_string(),
                symbol: sym.clone(),
                reason,
                confidence: conf,
                protocol: row.protocol.clone(),
                tls_owner_hint: row.tls_owner_hint,
            });
        }
    }
    out
}

/// Scan a whole file (multi-kind).
pub fn scan(
    source: &str,
    lang: Lang,
    catalog: &Catalog,
    symbols: &SymbolTable,
) -> Vec<Match> {
    let mut out: Vec<Match> = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let line_no = (i as u32) + 1;
        out.extend(scan_line(line, line_no, lang, catalog, symbols));
    }
    // De-duplicate by (api_name, line): multiple catalog rows can match the
    // same line; keep the one with the highest confidence.
    out.sort_by(|a, b| {
        a.api_name
            .cmp(&b.api_name)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| b.confidence.total_cmp(&a.confidence))
    });
    dedup(out)
}

/// Boost by reason: literal = 0.0, alias/subclass/di = +0.05, import = +0.03.
fn boost_for(reason: Reason) -> f32 {
    match reason {
        Reason::Literal => 0.0,
        Reason::Alias | Reason::Subclass | Reason::Di => 0.05,
        Reason::Import => 0.03,
    }
}

/// Classify the *reason* a match got (plan 02).
fn classify_reason(
    symbol: &str,
    symbols: &SymbolTable,
    framework: &str,
    lang: Lang,
) -> Reason {
    if symbols.has_alias(symbol) {
        return Reason::Alias;
    }
    if symbols.has_class(symbol) {
        return Reason::Subclass;
    }
    if symbols.has_di(symbol) {
        return Reason::Di;
    }
    // If the framework is recorded as an import in the file, that validates
    // the match even when no alias is present.
    if symbols.has_dep(framework) {
        return Reason::Import;
    }
    if lang == Lang::Cs && symbols.has_dep("_core") {
        return Reason::Import;
    }
    Reason::Literal
}

/// Extract a best-effort symbol from the line.
fn extract_symbol(line: &str) -> String {
    lazy_compile_extract().find(line)
        .map(|m| {
            let s = m.as_str();
            s.trim_end_matches('(').trim().to_string()
        })
        .unwrap_or_else(|| line.trim().to_string())
}

/// Compile the symbol-extraction regex once.
fn lazy_compile_extract() -> &'static regex::Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)\b[a-z_][a-z_0-9]*(?:\.[a-z_][a-z_0-9]*)+\b|\b[a-zA-Z_][a-zA-Z_0-9]*\s*\(",
        )
        .expect("extract_symbol regex should compile")
    })
}

/// Keep only the first (highest confidence) per (api_name, line) pair.
/// Expects input already sorted by (api_name, line, confidence desc).
fn dedup(v: Vec<Match>) -> Vec<Match> {
    if v.is_empty() {
        return v;
    }
    let mut out: Vec<Match> = Vec::with_capacity(v.len());
    for m in v {
        let dominated = out.last().map_or(false, |prev| {
            prev.api_name == m.api_name && prev.line == m.line
        });
        if !dominated {
            out.push(m);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::symbol::{self, SymbolTable};

    fn cat() -> Catalog {
        Catalog::built_in().unwrap()
    }

    #[test]
    fn scan_line_matches_js_fetch() {
        let c = cat();
        let sym = SymbolTable::default();
        let hits = scan_line("  fetch('https://api.example.com/data')", 1, Lang::Js, &c, &sym);
        assert!(!hits.is_empty(), "fetch should match");
        assert_eq!(hits[0].api_name, "js.fetch");
    }

    #[test]
    fn scan_line_matches_py_requests() {
        let c = cat();
        let sym = SymbolTable::default();
        let hits = scan_line("  requests.get('https://api.example.com')", 1, Lang::Py, &c, &sym);
        assert!(!hits.is_empty(), "requests.get should match");
        assert_eq!(hits[0].api_name, "py.requests");
    }

    #[test]
    fn scan_line_no_match_returns_empty() {
        let c = cat();
        let sym = SymbolTable::default();
        let hits = scan_line("let x = 42;", 1, Lang::Js, &c, &sym);
        assert!(hits.is_empty());
    }

    #[test]
    fn dedup_keeps_highest_confidence() {
        let m1 = Match {
            kind: Kind::Client,
            api_name: "a".into(),
            framework: "f".into(),
            line: 1,
            line_text: "".into(),
            symbol: "".into(),
            reason: Reason::Literal,
            confidence: 0.8,
            protocol: None,
            tls_owner_hint: None,
        };
        let mut m2 = m1.clone();
        m2.confidence = 0.9;
        // dedup keeps first after sort by (api_name, line), highest-conf first
        let mut v = vec![m1, m2];
        v.sort_by(|a, b| {
            a.api_name.cmp(&b.api_name)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| b.confidence.total_cmp(&a.confidence))
        });
        let result = dedup(v);
        assert_eq!(result.len(), 1);
        assert!((result[0].confidence - 0.9).abs() < 0.01);
    }

    #[test]
    fn classify_reason_alias() {
        let mut sym = symbol::build(Lang::Js, "const api = axios.create({})");
        // "api" is an alias for "axios"
        assert!(sym.has_alias("api"));
        let reason = classify_reason("api", &sym, "axios", Lang::Js);
        assert_eq!(reason, Reason::Alias);
    }

    #[test]
    fn classify_reason_import() {
        let sym = symbol::build(Lang::Py, "import requests");
        let reason = classify_reason("get", &sym, "requests", Lang::Py);
        assert_eq!(reason, Reason::Import);
    }

    #[test]
    fn classify_reason_literal() {
        let sym = SymbolTable::default();
        let reason = classify_reason("fetch", &sym, "web", Lang::Js);
        assert_eq!(reason, Reason::Literal);
    }

    #[test]
    fn extract_symbol_from_call() {
        let s = extract_symbol("  requests.get('https://example.com')");
        assert!(s.contains("requests.get") || s.contains("requests"), "got: {s}");
    }
}
