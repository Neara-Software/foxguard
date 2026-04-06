use foxguard::rules::RuleRegistry;
use foxguard::Language;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

#[test]
fn website_rule_inventory_matches_registry_counts() {
    let inventory_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("www")
        .join("src")
        .join("data")
        .join("rules.ts");

    let source =
        std::fs::read_to_string(&inventory_path).expect("failed to read website rule inventory");

    let rule_id_re = Regex::new(r"id:\s*'([a-z]+?)/").expect("invalid regex");
    let mut website_counts: HashMap<&str, usize> = HashMap::new();
    for captures in rule_id_re.captures_iter(&source) {
        let slug = captures.get(1).expect("missing slug").as_str();
        *website_counts.entry(slug).or_default() += 1;
    }

    let registry = RuleRegistry::new();
    let actual_counts = HashMap::from([
        (
            "js",
            registry.rules_for_language(Language::JavaScript).len(),
        ),
        ("py", registry.rules_for_language(Language::Python).len()),
        ("go", registry.rules_for_language(Language::Go).len()),
        ("rb", registry.rules_for_language(Language::Ruby).len()),
        ("java", registry.rules_for_language(Language::Java).len()),
        ("php", registry.rules_for_language(Language::Php).len()),
        ("rs", registry.rules_for_language(Language::Rust).len()),
        ("cs", registry.rules_for_language(Language::CSharp).len()),
        ("swift", registry.rules_for_language(Language::Swift).len()),
    ]);

    for (slug, count) in actual_counts {
        let website_count = website_counts.get(slug).copied().unwrap_or_default();
        assert_eq!(
            website_count, count,
            "website inventory count mismatch for {}: expected {}, found {}",
            slug, count, website_count
        );
    }
}
