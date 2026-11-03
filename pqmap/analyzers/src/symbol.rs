//! Per-file symbol table (plan 02) + the builder.
//!
//! We record only the *facts* the detector's `Reason` classifier needs:
//!   - `alias`  : `const api = axios.create(base)` / `import x as y from 'axios'`
//!   - `class`  : `class C extends B` (JS/TS) / `class C : B` (C#, Python)
//!   - `di`     : `services.AddHttpClient<T>()` (C#)
//!   - `dep`    : an import / `using` of a package (validates a match)
//!
//! This is the "scope-aware, not global-string matching" the plan requires (a
//! bare `axios` would match every file that imports it; instead we only attach
//! alias/subclass/di reasons to symbols *declared in this file*).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::Lang;

/// A local alias: `alias = base` in JS/TS (factory aliasing), or
/// `import x as y` from a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub alias: String,
    pub base: String,
    pub line: u32,
}

/// A class / interface definition: `name` is the new type, `parent` is what it
/// extends / implements (first, for `: Base, IFace` we take the first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDef {
    pub name: String,
    pub parent: String,
    pub line: u32,
}

/// A DI registration. `service` is e.g. `IHttpClientFactory`; `target` is the
/// named-client id or typed generic, when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiRegistration {
    pub service: String,
    pub target: Option<String>,
    pub line: u32,
}

/// A dependency declaration (`import axios from 'axios'`, `using System.Net.Http;`,
/// `import requests`). `name` is the package / namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub bindings: Vec<String>,
    pub line: u32,
}

/// Per-file symbol table. One table belongs to exactly one file.
#[derive(Debug, Default)]
pub struct SymbolTable {
    pub lang: Option<Lang>,
    pub alias: Vec<Alias>,
    pub class: Vec<ClassDef>,
    pub di: Vec<DiRegistration>,
    pub dep: Vec<Dependency>,
    /// Set of package-name strings (for `has_dep`).
    pub dep_names: BTreeSet<String>,
    /// Set of alias strings (for `has_alias`).
    pub alias_names: BTreeSet<String>,
    /// Set of class-name strings (for `has_class`).
    pub class_names: BTreeSet<String>,
    /// Set of DI-service strings (for `has_di`).
    pub di_names: BTreeSet<String>,
}

impl SymbolTable {
    pub fn new(lang: Lang) -> Self {
        Self {
            lang: Some(lang),
            ..Default::default()
        }
    }

    pub fn add_alias(&mut self, a: Alias) {
        self.alias_names.insert(a.alias.clone());
        self.alias.push(a);
    }
    pub fn add_class(&mut self, c: ClassDef) {
        self.class_names.insert(c.name.clone());
        self.class.push(c);
    }
    pub fn add_di(&mut self, d: DiRegistration) {
        self.di_names.insert(d.service.clone());
        self.di.push(d);
    }
    pub fn add_dep(&mut self, d: Dependency) {
        self.dep_names.insert(d.name.clone());
        self.dep.push(d);
    }

    pub fn has_alias(&self, name: &str) -> bool {
        self.alias_names.contains(name)
    }
    pub fn has_class(&self, name: &str) -> bool {
        self.class_names.contains(name)
    }
    pub fn has_di(&self, name: &str) -> bool {
        self.di_names.contains(name)
    }
    pub fn has_dep(&self, name: &str) -> bool {
        self.dep_names.contains(name) || self.dep_names.iter().any(|n| {
            n.starts_with(name) || name.starts_with(n.as_str()) || n.split('.').any(|p| p == name)
        })
    }
}

// ---------------------------------------------------------------------------
// Builder. Regexes are compiled once via LazyLock and reused across all files.
// ---------------------------------------------------------------------------

// JS/TS patterns
static JS_IMPORT_AS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)import\s+\w+\s+as\s+(\w+)\s+from\s+['"][^'"]+['"]"#).unwrap()
});
static JS_FROM_PKG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)from\s+['"]([^'"]+)['"]"#).unwrap()
});
static JS_FACTORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:const|let|var)\s+(\w+)\s*=\s*([A-Za-z_$][\w$]*)\.(create|instance|client)\s*\(").unwrap()
});
static JS_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)class\s+([A-Za-z_$][\w$]*)\s+(?:extends|implements)\s+([A-Za-z_$][\w$.]*)").unwrap()
});

// C# patterns
static CS_USING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*using\s+([A-Za-z_][\w.]*);").unwrap()
});
static CS_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)class\s+([A-Za-z_][\w]*)\s*:\s*([A-Za-z_][\w.,\s]*)").unwrap()
});
static CS_DI_GENERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)AddHttpClient\s*<\s*([A-Za-z_][\w]*)\s*>").unwrap()
});
static CS_DI_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)AddHttpClient\s*\(").unwrap()
});

// Python patterns
static PY_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*import\s+([a-zA-Z_][\w.]*)").unwrap()
});
static PY_FROM_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*from\s+([a-zA-Z_][\w.]*)\s+import\s+([\w, ]+)").unwrap()
});
static PY_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)class\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)").unwrap()
});

// Java patterns
static JAVA_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*import\s+([a-zA-Z_][\w.]*)\s*;").unwrap()
});
static JAVA_CLASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)class\s+([A-Za-z_][\w]*)\s+(?:extends|implements)\s+([A-Za-z_][\w.]*)").unwrap()
});
static JAVA_DI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"@(Autowired|Bean|Inject)\b").unwrap()
});

// Rust patterns
static RUST_USE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*use\s+([a-zA-Z_][\w:]*)\b").unwrap()
});
static RUST_STRUCT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:pub\s+)?struct\s+([A-Z]\w*)\b").unwrap()
});

// Go patterns
static GO_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s*import\s+"([^"]+)""#).unwrap()
});
static GO_MULTI_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*"([^"]+)"\s*$"#).unwrap()
});
static GO_TYPE_STRUCT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*type\s+([A-Z]\w*)\s+struct\b").unwrap()
});

/// Build the symbol table for one source file.
pub fn build(lang: Lang, source: &str) -> SymbolTable {
    let mut t = SymbolTable::new(lang);
    for (i, line) in source.lines().enumerate() {
        let n = (i as u32) + 1;
        match lang {
            Lang::Js | Lang::Ts => js_ts(&mut t, line, n),
            Lang::Cs => cs(&mut t, line, n),
            Lang::Py => py(&mut t, line, n),
            Lang::Java => java(&mut t, line, n),
            Lang::Go => go(&mut t, line, n),
            Lang::Rust => rust(&mut t, line, n),
        }
    }
    t
}

fn js_ts(t: &mut SymbolTable, line: &str, n: u32) {
    // import x as y from 'pkg'
    if let Some(c) = JS_IMPORT_AS.captures(line).map(|m| m[1].to_string()) {
        let base = JS_FROM_PKG
            .captures(line)
            .map(|m| m[1].to_string())
            .unwrap_or_default();
        let base_clone = base.clone();
        t.add_alias(Alias { alias: c, base: base_clone, line: n });
        if !base.is_empty() {
            t.add_dep(Dependency { name: base, bindings: vec![], line: n });
        }
    }
    // import { a, b } from 'pkg'  /  import pkg from 'pkg'
    if let Some(base) = extract_js_package(line) {
        t.add_dep(Dependency { name: base, bindings: vec![], line: n });
    }
    // const api = pkg.create(...)  (factory aliasing)
    if let Some((alias, base)) = JS_FACTORY
        .captures(line)
        .map(|m| (m[1].to_string(), m[2].to_string()))
    {
        t.add_alias(Alias { alias, base, line: n });
    }
    // class C extends B
    if let Some((name, parent)) = JS_CLASS
        .captures(line)
        .map(|m| (m[1].to_string(), m[2].to_string()))
    {
        t.add_class(ClassDef { name, parent, line: n });
    }
}

fn cs(t: &mut SymbolTable, line: &str, n: u32) {
    if let Some(ns) = CS_USING.captures(line).map(|m| m[1].to_string()) {
        t.add_dep(Dependency { name: ns, bindings: vec![], line: n });
    }
    if let Some((name, parent)) = CS_CLASS
        .captures(line)
        .map(|m| (m[1].to_string(), m[2].trim().to_string()))
    {
        t.add_class(ClassDef { name, parent, line: n });
    }
    // services.AddHttpClient<T>() or AddHttpClient("name")  (plan 02 DI)
    if let Some(gen) = CS_DI_GENERIC
        .captures(line)
        .map(|m| m[1].to_string())
        .filter(|s| !s.is_empty())
    {
        t.add_di(DiRegistration {
            service: "IHttpClientFactory".to_string(),
            target: Some(gen),
            line: n,
        });
    } else if CS_DI_CALL.is_match(line) {
        t.add_di(DiRegistration {
            service: "IHttpClientFactory".to_string(),
            target: None,
            line: n,
        });
    }
}

fn py(t: &mut SymbolTable, line: &str, n: u32) {
    if let Some(pkg) = PY_IMPORT.captures(line).map(|m| m[1].to_string()) {
        t.add_dep(Dependency { name: pkg, bindings: vec![], line: n });
    }
    if let Some((pkg, bindings)) = PY_FROM_IMPORT.captures(line).map(|m| {
        (
            m[1].to_string(),
            m[2].split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
        )
    }) {
        t.add_dep(Dependency {
            name: pkg,
            bindings,
            line: n,
        });
    }
    if let Some((name, parent)) = PY_CLASS.captures(line).map(|m| {
        (
            m[1].to_string(),
            m[2].trim()
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_string(),
        )
    }) {
        t.add_class(ClassDef { name, parent, line: n });
    }
}

fn java(t: &mut SymbolTable, line: &str, n: u32) {
    // import pkg.Class;
    if let Some(pkg) = JAVA_IMPORT.captures(line).map(|m| m[1].to_string()) {
        t.add_dep(Dependency { name: pkg, bindings: vec![], line: n });
    }
    // class Foo extends Bar / implements Bar
    if let Some((name, parent)) = JAVA_CLASS
        .captures(line)
        .map(|m| (m[1].to_string(), m[2].to_string()))
    {
        t.add_class(ClassDef { name, parent, line: n });
    }
    // @Autowired / @Bean / @Inject DI annotations
    if let Some(service) = JAVA_DI.captures(line).map(|m| m[1].to_string()) {
        t.add_di(DiRegistration {
            service,
            target: None,
            line: n,
        });
    }
}

fn go(t: &mut SymbolTable, line: &str, n: u32) {
    // Single-line import: import "pkg"
    if let Some(pkg) = GO_IMPORT.captures(line).map(|m| m[1].to_string()) {
        t.add_dep(Dependency { name: pkg, bindings: vec![], line: n });
    }
    // Multi-import block member: a quoted path containing / or .
    if let Some(pkg) = GO_MULTI_IMPORT
        .captures(line)
        .map(|m| m[1].to_string())
        .filter(|s| s.contains('/') || s.contains('.'))
    {
        t.add_dep(Dependency { name: pkg, bindings: vec![], line: n });
    }
    // type Foo struct
    if let Some(name) = GO_TYPE_STRUCT.captures(line).map(|m| m[1].to_string()) {
        t.add_class(ClassDef { name, parent: String::new(), line: n });
    }
}

fn rust(t: &mut SymbolTable, line: &str, n: u32) {
    // use crate_name::module  or  use std::io
    if let Some(pkg) = RUST_USE.captures(line).map(|m| m[1].to_string()) {
        // Normalize: take root crate (first segment before ::)
        let root = pkg.split("::").next().unwrap_or(&pkg).to_string();
        t.add_dep(Dependency { name: root, bindings: vec![], line: n });
    }
    // struct Foo
    if let Some(name) = RUST_STRUCT.captures(line).map(|m| m[1].to_string()) {
        t.add_class(ClassDef { name, parent: String::new(), line: n });
    }
}

/// Extract the JS/TS import package (`import ... from 'pkg'`).
fn extract_js_package(line: &str) -> Option<String> {
    JS_FROM_PKG
        .captures(line)
        .map(|m| m[1].to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- JS/TS ----

    #[test]
    fn js_import_from() {
        let t = build(Lang::Js, "import axios from 'axios';\n");
        assert!(t.has_dep("axios"));
    }

    #[test]
    fn js_import_as_alias() {
        let t = build(Lang::Js, "import ax as http from 'axios';\n");
        assert!(t.has_alias("http"));
    }

    #[test]
    fn js_class_extends() {
        let t = build(Lang::Js, "class MyClient extends HttpClient {}\n");
        assert!(t.has_class("MyClient"));
        assert_eq!(t.class[0].parent, "HttpClient");
    }

    #[test]
    fn js_factory_alias() {
        let t = build(Lang::Js, "const api = axios.create({ baseURL: '/' });\n");
        assert!(t.has_alias("api"));
        assert_eq!(t.alias[0].base, "axios");
    }

    // ---- C# ----

    #[test]
    fn cs_using() {
        let t = build(Lang::Cs, "using System.Net.Http;\n");
        assert!(t.has_dep("System.Net.Http"));
    }

    #[test]
    fn cs_class_inheritance() {
        let t = build(Lang::Cs, "public class Foo : Bar\n");
        assert!(t.has_class("Foo"));
        assert_eq!(t.class[0].parent, "Bar");
    }

    #[test]
    fn cs_di_http_client_factory() {
        let t = build(Lang::Cs, "services.AddHttpClient<MyClient>();\n");
        assert!(t.has_di("IHttpClientFactory"));
        assert_eq!(t.di[0].target.as_deref(), Some("MyClient"));
    }

    // ---- Python ----

    #[test]
    fn py_import() {
        let t = build(Lang::Py, "import requests\n");
        assert!(t.has_dep("requests"));
    }

    #[test]
    fn py_from_import() {
        let t = build(Lang::Py, "from fastapi import FastAPI, Request\n");
        assert!(t.has_dep("fastapi"));
        assert_eq!(t.dep[0].bindings, vec!["FastAPI", "Request"]);
    }

    #[test]
    fn py_class() {
        let t = build(Lang::Py, "class MyApp(FastAPI):\n");
        assert!(t.has_class("MyApp"));
        assert_eq!(t.class[0].parent, "FastAPI");
    }

    // ---- Java ----

    #[test]
    fn java_import() {
        let t = build(Lang::Java, "import okhttp3.OkHttpClient;\n");
        assert!(t.has_dep("okhttp3.OkHttpClient"));
    }

    #[test]
    fn java_class_extends() {
        let t = build(Lang::Java, "public class PayService extends BaseService {\n");
        assert!(t.has_class("PayService"));
        assert_eq!(t.class[0].parent, "BaseService");
    }

    #[test]
    fn java_di_annotation() {
        let t = build(Lang::Java, "    @Autowired\n");
        assert!(t.has_di("Autowired"));
    }

    // ---- Go ----

    #[test]
    fn go_single_import() {
        let t = build(Lang::Go, "import \"net/http\"\n");
        assert!(t.has_dep("net/http"));
    }

    #[test]
    fn go_multi_import_line() {
        let src = "import (\n\t\"net/http\"\n\t\"google.golang.org/grpc\"\n)\n";
        let t = build(Lang::Go, src);
        assert!(t.has_dep("net/http"));
        assert!(t.has_dep("google.golang.org/grpc"));
    }

    #[test]
    fn go_type_struct() {
        let t = build(Lang::Go, "type Server struct {\n");
        assert!(t.has_class("Server"));
    }

    #[test]
    fn has_dep_prefix_matching() {
        let t = build(Lang::Go, "import \"net/http\"\n");
        assert!(t.has_dep("net/http"));
        assert!(t.has_dep("net"));
    }
}
