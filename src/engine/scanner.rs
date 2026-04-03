use crate::rules::RuleRegistry;
use crate::{Finding, Language};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;

/// Detect language from file extension.
fn detect_language(path: &Path) -> Option<Language> {
    match path.extension()?.to_str()? {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "py" | "pyw" => Some(Language::Python),
        "go" => Some(Language::Go),
        "rb" | "rake" | "gemspec" => Some(Language::Ruby),
        "java" => Some(Language::Java),
        "php" => Some(Language::Php),
        "rs" => Some(Language::Rust),
        _ => None,
    }
}

/// Scan a directory (or single file) and return all findings.
pub fn scan_directory(root: &str, registry: &RuleRegistry) -> Vec<Finding> {
    let root_path = Path::new(root);

    let files: Vec<_> = if root_path.is_file() {
        if let Some(lang) = detect_language(root_path) {
            vec![(root_path.to_path_buf(), lang)]
        } else {
            vec![]
        }
    } else {
        WalkBuilder::new(root)
            .hidden(true) // skip hidden files
            .git_ignore(true) // respect .gitignore
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .filter_map(|entry| {
                let path = entry.into_path();
                detect_language(&path).map(|lang| (path, lang))
            })
            .collect()
    };

    scan_files(scan_root(root_path), files, registry)
}

/// Scan an explicit list of paths.
pub fn scan_paths(paths: &[PathBuf], registry: &RuleRegistry) -> Vec<Finding> {
    scan_paths_with_root(Path::new("."), paths, registry)
}

/// Scan an explicit list of paths relative to a scan root.
pub fn scan_paths_with_root(
    root: &Path,
    paths: &[PathBuf],
    registry: &RuleRegistry,
) -> Vec<Finding> {
    let files = paths
        .iter()
        .filter_map(|path| detect_language(path).map(|lang| (path.clone(), lang)))
        .collect();
    scan_files(scan_root(root), files, registry)
}

fn scan_files(
    scan_root: &Path,
    files: Vec<(PathBuf, Language)>,
    registry: &RuleRegistry,
) -> Vec<Finding> {
    let findings = Mutex::new(Vec::new());

    files.par_iter().for_each(|(path, language)| {
        let Ok(source) = std::fs::read_to_string(path) else {
            return;
        };

        let Some(tree) = super::parser::parse_file(&source, *language) else {
            return;
        };

        let file_str = path.display().to_string();
        let relative_path = relative_scan_path(scan_root, path);
        let rules = registry.rules_for_language(*language);

        for rule in rules {
            if !rule.applies_to_path(&relative_path) {
                continue;
            }
            let mut rule_findings = rule.check(&source, &tree);
            for f in &mut rule_findings {
                f.file = file_str.clone();
            }
            if !rule_findings.is_empty() {
                findings.lock().unwrap().extend(rule_findings);
            }
        }
    });

    let mut results = findings.into_inner().unwrap();
    results.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    results
}

fn scan_root(path: &Path) -> &Path {
    if path.is_file() {
        path.parent().unwrap_or_else(|| Path::new("."))
    } else {
        path
    }
}

fn relative_scan_path(scan_root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(scan_root).unwrap_or(path).to_path_buf()
}
