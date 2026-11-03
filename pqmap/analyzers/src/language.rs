//! Language tag + extension mapping (plan 02).

use serde::{Deserialize, Serialize};

/// A first-class language tag (matches `pq_core::LanguageTag` shapes we use).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lang {
    Js,
    Ts,
    Cs,
    Py,
    Java,
    Go,
    Rust,
}

impl Lang {
    pub fn from_extension(ext: &str) -> Option<Lang> {
        match ext {
            "js" | "mjs" | "cjs" => Some(Lang::Js),
            "ts" | "tsx" => Some(Lang::Ts),
            "cs" => Some(Lang::Cs),
            "py" => Some(Lang::Py),
            "java" => Some(Lang::Java),
            "go" => Some(Lang::Go),
            "rs" => Some(Lang::Rust),
            _ => None,
        }
    }

    /// Human label for CLI/UI.
    pub fn label(&self) -> &'static str {
        match self {
            Lang::Js => "js",
            Lang::Ts => "ts",
            Lang::Cs => "c#",
            Lang::Py => "python",
            Lang::Java => "java",
            Lang::Go => "go",
            Lang::Rust => "rust",
        }
    }
}
