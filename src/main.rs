use clap::Parser;
use foxguard::cli::{Cli, OutputFormat};
use foxguard::engine::scan_directory;
use foxguard::rules::semgrep_compat::load_semgrep_rules;
use foxguard::rules::RuleRegistry;
use std::path::Path;

fn main() {
    let cli = Cli::parse();
    let mut registry = RuleRegistry::new();

    let scan_path = Path::new(&cli.path);
    if !scan_path.exists() {
        eprintln!("Error: path '{}' does not exist", cli.path);
        std::process::exit(2);
    }

    // Load external Semgrep YAML rules if --rules is provided
    if let Some(ref rules_path) = cli.rules {
        let path = Path::new(rules_path);
        if !path.exists() {
            eprintln!("Error: rules path '{}' does not exist", rules_path);
            std::process::exit(2);
        }
        let semgrep_rules = load_semgrep_rules(path);
        let count = semgrep_rules.len();
        for rule in semgrep_rules {
            registry.register(rule);
        }
        if count > 0 {
            eprintln!("Loaded {} Semgrep rule(s) from {}", count, rules_path);
        }
    }

    let mut findings = scan_directory(&cli.path, &registry);

    // Filter by severity if specified
    if let Some(ref min_severity) = cli.severity {
        let min = min_severity.to_severity();
        findings.retain(|f| f.severity >= min);
    }

    match cli.format {
        OutputFormat::Terminal => foxguard::report::terminal::print_findings(&findings),
        OutputFormat::Json => foxguard::report::json::print_json(&findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&findings),
    }

    // Exit with non-zero code if findings exist
    if !findings.is_empty() {
        std::process::exit(1);
    }
}
