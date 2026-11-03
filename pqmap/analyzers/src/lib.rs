//! `pq-analyzers` — language-aware endpoint discovery (plan 02).
//!
//! The pipeline, per file:
//!
//!   parse (lightweight, deterministic)
//!     → symbol table (imports, aliases, subclasses, DI registrations)
//!     → call-site matcher (against the framework API catalog)
//!     → destination binding (1 hop)
//!     → emit NetworkEdge(s) + Evidence + resolution chain
//!
//! The catalog is data, not code (TOML): adding a framework is adding rows.
//! We use regex + structured line scanning rather than a full parser: it is
//! deterministic, has no build burden, and covers the V1 acceptance fixtures
//! (aliasing / subclass / DI). Confidence + the resolution chain carry the
//! "why did we match this" story (plan 02 `--explain` fixture coverage).

pub mod catalog;
pub mod detector;
pub mod infra;
pub mod language;
pub mod pipeline;
pub mod platform;
pub mod pq_config;
pub mod symbol;
pub mod walk;

pub use catalog::{Catalog, EntryKind, Row, TlsOwnerHint};
pub use detector::{scan, scan_line, Kind, Match, Reason};
pub use infra::{InfraComponent, IaCDetector};
pub use language::Lang;
pub use platform::{DockerBase, Os, PlatformFacts};
pub use symbol::{
    build, Alias, ClassDef, DiRegistration, Dependency, SymbolTable,
};
pub use pipeline::{AnalysisContext, ScanOptions};
pub use pq_config::{detect_pq_config, detect_pq_config_from_files, upgrade_pq_enabled};
pub use walk::RepoFiles;
