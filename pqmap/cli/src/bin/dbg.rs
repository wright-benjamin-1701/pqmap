fn main() {
    let s = include_str!("/home/benwright/Documents/GitHub/pqc-app/pqmap/analyzers/src/embedded_catalog.toml");
    #[derive(serde::Deserialize)]
    struct Doc { #[serde(default)] row: Vec<Row2> }
    #[derive(serde::Deserialize, Clone)]
    struct Row2 {
        #[serde(default)] lang: Option<String>,
        #[serde(default)] kind: Option<String>,
        #[serde(default)] pattern: Option<String>,
        #[serde(default)] api_name: Option<String>,
    }
    let doc: Doc = match toml::from_str(s) {
        Ok(d) => d,
        Err(e) => { println!("TOML parse failed: {e}"); return; }
    };
    let line = "    r = requests.get(\"https://api.stripe.com/v1/charges\", timeout=5)";
    for r in doc.row.iter() {
        let pat = r.pattern.clone().unwrap_or_default();
        let compiled = regex::Regex::new(&pat).ok();
        let matches = compiled.as_ref().is_some_and(|re| re.is_match(line));
        println!(
            "  {:?}/{:?}  api={}  comp={} matches_fixture={}",
            r.lang.as_deref(),
            r.kind.as_deref(),
            r.api_name.as_deref().unwrap_or("?"),
            if compiled.is_some() { "ok" } else { "FAIL" },
            matches,
        );
    }
}
