use clap::Parser;
use foxguard::baseline::{load_baseline, suppress_with_baseline, write_baseline};
use foxguard::cli::{BaselineArgs, Cli, Command, InitArgs, OutputFormat, ScanArgs, SecretsArgs};
use foxguard::engine::{scan_directory, scan_paths};
use foxguard::git::changed_files;
use foxguard::rules::semgrep_compat::load_semgrep_rules;
use foxguard::rules::RuleRegistry;
use foxguard::secrets::{
    scan_directory_with_config as scan_secrets_directory,
    scan_paths_with_config as scan_secrets_paths, SecretScanConfig,
};
use std::path::{Path, PathBuf};

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Some(Command::Init(args)) => run_init(&args),
        Some(Command::Baseline(args)) => run_baseline(&args),
        Some(Command::Secrets(args)) => run_secrets(&args),
        None => run_scan(&cli.scan),
    };

    std::process::exit(exit_code);
}

fn build_registry(scan: &ScanArgs) -> RuleRegistry {
    let mut registry = if scan.no_builtins {
        RuleRegistry::empty()
    } else {
        RuleRegistry::new()
    };

    if let Some(ref rules_path) = scan.rules {
        let path = Path::new(rules_path);
        let semgrep_rules = load_semgrep_rules(path);
        let count = semgrep_rules.len();
        for rule in semgrep_rules {
            registry.register(rule);
        }
        if count > 0 {
            eprintln!("Loaded {} Semgrep rule(s) from {}", count, rules_path);
        }
    }

    registry
}

fn validate_scan_inputs(scan: &ScanArgs) -> Result<(), i32> {
    let scan_path = Path::new(&scan.path);
    if !scan_path.exists() {
        eprintln!("Error: path '{}' does not exist", scan.path);
        return Err(2);
    }

    if let Some(ref rules_path) = scan.rules {
        let path = Path::new(rules_path);
        if !path.exists() {
            eprintln!("Error: rules path '{}' does not exist", rules_path);
            return Err(2);
        }
    }

    Ok(())
}

fn collect_changed_targets(path: &str, changed: bool) -> Result<Option<Vec<PathBuf>>, i32> {
    if !changed {
        return Ok(None);
    }

    let scan_root = Path::new(path);
    let files = changed_files(scan_root).map_err(|e| {
        eprintln!("Error: failed to resolve changed files: {}", e);
        2
    })?;

    Ok(Some(files))
}

fn scan_findings(scan: &ScanArgs) -> Result<Vec<foxguard::Finding>, i32> {
    validate_scan_inputs(scan)?;

    let registry = build_registry(scan);
    let targets = collect_changed_targets(&scan.path, scan.changed)?;

    let mut findings = if let Some(files) = targets {
        scan_paths(&files, &registry)
    } else {
        scan_directory(&scan.path, &registry)
    };

    // Filter by severity if specified
    if let Some(ref min_severity) = scan.severity {
        let min = min_severity.to_severity();
        findings.retain(|f| f.severity >= min);
    }

    Ok(findings)
}

fn run_scan(scan: &ScanArgs) -> i32 {
    let mut findings = match scan_findings(scan) {
        Ok(findings) => findings,
        Err(code) => return code,
    };

    if let Some(ref path) = scan.write_baseline {
        if let Err(e) = write_baseline(Path::new(path), &findings) {
            eprintln!("Error: {}", e);
            return 2;
        }
        eprintln!("Wrote baseline to {}", path);
    }

    let baseline = match scan.baseline.as_ref() {
        Some(path) => match load_baseline(Path::new(path)) {
            Ok(baseline) => baseline,
            Err(e) => {
                eprintln!("Error: {}", e);
                return 2;
            }
        },
        None => None,
    };

    findings = suppress_with_baseline(findings, baseline.as_ref());

    match scan.format {
        OutputFormat::Terminal => foxguard::report::terminal::print_findings(&findings),
        OutputFormat::Json => foxguard::report::json::print_json(&findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&findings),
    }

    if !findings.is_empty() {
        return 1;
    }

    0
}

fn run_baseline(args: &BaselineArgs) -> i32 {
    let mut scan = args.scan.clone();
    scan.write_baseline = None;
    scan.baseline = None;

    let findings = match scan_findings(&scan) {
        Ok(findings) => findings,
        Err(code) => return code,
    };

    if let Err(e) = write_baseline(Path::new(&args.output), &findings) {
        eprintln!("Error: {}", e);
        return 2;
    }

    eprintln!(
        "Wrote baseline with {} finding(s) to {}",
        findings.len(),
        args.output
    );
    0
}

fn run_secrets(args: &SecretsArgs) -> i32 {
    let scan_path = Path::new(&args.path);
    if !scan_path.exists() {
        eprintln!("Error: path '{}' does not exist", args.path);
        return 2;
    }

    let config = match SecretScanConfig::from_inputs(
        scan_path,
        &args.exclude_paths,
        args.exclude_path_file.as_deref().map(Path::new),
        &args.ignored_rules,
    ) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 2;
        }
    };

    let targets = match collect_changed_targets(&args.path, args.changed) {
        Ok(targets) => targets,
        Err(code) => return code,
    };

    let mut findings = if let Some(files) = targets {
        scan_secrets_paths(scan_path, &files, &config)
    } else {
        scan_secrets_directory(&args.path, &config)
    };

    if let Some(ref path) = args.write_baseline {
        if let Err(e) = write_baseline(Path::new(path), &findings) {
            eprintln!("Error: {}", e);
            return 2;
        }
        eprintln!("Wrote secrets baseline to {}", path);
    }

    let baseline = match args.baseline.as_ref() {
        Some(path) => match load_baseline(Path::new(path)) {
            Ok(baseline) => baseline,
            Err(e) => {
                eprintln!("Error: {}", e);
                return 2;
            }
        },
        None => None,
    };

    findings = suppress_with_baseline(findings, baseline.as_ref());

    match args.format {
        OutputFormat::Terminal => foxguard::report::terminal::print_findings(&findings),
        OutputFormat::Json => foxguard::report::json::print_json(&findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&findings),
    }

    if !findings.is_empty() {
        return 1;
    }

    0
}

fn run_init(args: &InitArgs) -> i32 {
    let repo_root = Path::new(&args.path);
    if !repo_root.exists() {
        eprintln!("Error: path '{}' does not exist", args.path);
        return 2;
    }

    let hook_path = repo_root.join(&args.hook_path);
    if hook_path.exists() && !args.force {
        eprintln!(
            "Error: hook '{}' already exists; rerun with --force to overwrite",
            hook_path.display()
        );
        return 2;
    }

    if let Some(parent) = hook_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "Error: failed to create hook directory '{}': {}",
                parent.display(),
                e
            );
            return 2;
        }
    }

    let hook_contents = if args.no_baseline {
        "#!/usr/bin/env sh\nset -eu\nfoxguard --changed\nfoxguard secrets --changed\n".to_string()
    } else {
        format!(
            "#!/usr/bin/env sh\nset -eu\nfoxguard --changed --baseline \"{}\"\nfoxguard secrets --changed --baseline \"{}\"\n",
            args.baseline,
            args.secrets_baseline
        )
    };

    if let Err(e) = std::fs::write(&hook_path, hook_contents) {
        eprintln!(
            "Error: failed to write hook '{}': {}",
            hook_path.display(),
            e
        );
        return 2;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = match std::fs::metadata(&hook_path) {
            Ok(meta) => meta.permissions(),
            Err(e) => {
                eprintln!(
                    "Error: failed to read hook metadata '{}': {}",
                    hook_path.display(),
                    e
                );
                return 2;
            }
        };
        perms.set_mode(0o755);
        if let Err(e) = std::fs::set_permissions(&hook_path, perms) {
            eprintln!(
                "Error: failed to mark hook executable '{}': {}",
                hook_path.display(),
                e
            );
            return 2;
        }
    }

    if !args.no_baseline {
        let baseline_args = BaselineArgs {
            scan: ScanArgs {
                path: args.path.clone(),
                format: OutputFormat::Json,
                severity: None,
                rules: None,
                no_builtins: false,
                changed: false,
                baseline: None,
                write_baseline: None,
            },
            output: repo_root.join(&args.baseline).display().to_string(),
        };

        let code = run_baseline(&baseline_args);
        if code != 0 {
            return code;
        }

        let secrets_args = SecretsArgs {
            path: args.path.clone(),
            format: OutputFormat::Json,
            changed: false,
            baseline: None,
            write_baseline: Some(repo_root.join(&args.secrets_baseline).display().to_string()),
            exclude_paths: Vec::new(),
            exclude_path_file: None,
            ignored_rules: Vec::new(),
        };

        let code = run_secrets(&secrets_args);
        if code != 0 && code != 1 {
            return code;
        }
    }

    eprintln!("Installed pre-commit hook at {}", hook_path.display());
    0
}
