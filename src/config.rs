use crate::cli::{ScanArgs, SecretsArgs, SeverityFilter};
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};

const CONFIG_NAMES: [&str; 4] = [
    ".foxguard.yml",
    ".foxguard.yaml",
    "foxguard.yml",
    "foxguard.yaml",
];

#[derive(Debug, Clone, Default)]
pub struct FoxguardConfig {
    pub scan: ScanConfig,
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    pub rules: Option<String>,
    pub no_builtins: bool,
    pub severity: Option<SeverityFilter>,
    pub baseline: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SecretsConfig {
    pub baseline: Option<String>,
    pub exclude_paths: Vec<String>,
    pub exclude_path_file: Option<String>,
    pub ignored_rules: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawFoxguardConfig {
    #[serde(default)]
    scan: RawScanConfig,
    #[serde(default)]
    secrets: RawSecretsConfig,
}

#[derive(Debug, Deserialize, Default)]
struct RawScanConfig {
    rules: Option<String>,
    no_builtins: Option<bool>,
    severity: Option<SeverityFilter>,
    baseline: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSecretsConfig {
    baseline: Option<String>,
    #[serde(default)]
    exclude_paths: Vec<String>,
    exclude_path_file: Option<String>,
    #[serde(default)]
    ignore_rules: Vec<String>,
}

pub fn load_for_scan(
    scan_path: &Path,
    explicit_path: Option<&str>,
) -> Result<Option<FoxguardConfig>, String> {
    let Some(path) = resolve_config_path(scan_path, explicit_path)? else {
        return Ok(None);
    };

    let path = path.canonicalize().unwrap_or_else(|_| path.clone());
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let allowed_root = resolve_allowed_root(scan_path, config_dir);

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config {}: {}", path.display(), e))?;
    let raw: RawFoxguardConfig = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse config {}: {}", path.display(), e))?;

    Ok(Some(FoxguardConfig::from_raw(
        raw,
        config_dir,
        &allowed_root,
    )?))
}

pub fn apply_scan_defaults(scan: &mut ScanArgs, config: Option<&FoxguardConfig>) {
    let Some(config) = config else {
        return;
    };

    if scan.rules.is_none() {
        scan.rules = config.scan.rules.clone();
    }
    if !scan.no_builtins && config.scan.no_builtins {
        scan.no_builtins = true;
    }
    if scan.severity.is_none() {
        scan.severity = config.scan.severity;
    }
    if scan.baseline.is_none() {
        scan.baseline = config.scan.baseline.clone();
    }
}

pub fn apply_secrets_defaults(args: &mut SecretsArgs, config: Option<&FoxguardConfig>) {
    let Some(config) = config else {
        return;
    };

    if args.baseline.is_none() {
        args.baseline = config.secrets.baseline.clone();
    }
    if args.exclude_path_file.is_none() {
        args.exclude_path_file = config.secrets.exclude_path_file.clone();
    }
    args.exclude_paths
        .extend(config.secrets.exclude_paths.clone());
    args.ignored_rules
        .extend(config.secrets.ignored_rules.clone());
}

impl FoxguardConfig {
    fn from_raw(
        raw: RawFoxguardConfig,
        config_dir: &Path,
        allowed_root: &Path,
    ) -> Result<Self, String> {
        let scan_rules = raw
            .scan
            .rules
            .map(|path| resolve_value_path(config_dir, allowed_root, "scan.rules", &path))
            .transpose()?;
        let scan_baseline = raw
            .scan
            .baseline
            .map(|path| resolve_value_path(config_dir, allowed_root, "scan.baseline", &path))
            .transpose()?;
        let secrets_baseline = raw
            .secrets
            .baseline
            .map(|path| resolve_value_path(config_dir, allowed_root, "secrets.baseline", &path))
            .transpose()?;
        let secrets_exclude_paths = raw
            .secrets
            .exclude_paths
            .into_iter()
            .map(|path| {
                resolve_value_path(config_dir, allowed_root, "secrets.exclude_paths", &path)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let secrets_exclude_path_file = raw
            .secrets
            .exclude_path_file
            .map(|path| {
                resolve_value_path(config_dir, allowed_root, "secrets.exclude_path_file", &path)
            })
            .transpose()?;

        Ok(Self {
            scan: ScanConfig {
                rules: scan_rules,
                no_builtins: raw.scan.no_builtins.unwrap_or(false),
                severity: raw.scan.severity,
                baseline: scan_baseline,
            },
            secrets: SecretsConfig {
                baseline: secrets_baseline,
                exclude_paths: secrets_exclude_paths,
                exclude_path_file: secrets_exclude_path_file,
                ignored_rules: raw.secrets.ignore_rules,
            },
        })
    }
}

fn resolve_config_path(
    scan_path: &Path,
    explicit_path: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    if let Some(path) = explicit_path {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(format!("Config path '{}' does not exist", path.display()));
        }
        return Ok(Some(path));
    }

    let start = scan_path
        .canonicalize()
        .unwrap_or_else(|_| scan_path.to_path_buf());
    let start = if start.is_file() {
        start
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        start
    };

    for dir in start.ancestors() {
        for name in CONFIG_NAMES {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(Some(candidate));
            }
        }
    }

    Ok(None)
}

fn resolve_value_path(
    base: &Path,
    allowed_root: &Path,
    field: &str,
    value: &str,
) -> Result<String, String> {
    let joined = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        base.join(value)
    };
    let resolved = resolve_path_for_boundary(&joined);

    if !resolved.starts_with(allowed_root) {
        return Err(format!(
            "Config path '{}' for {} escapes the project root {}",
            value,
            field,
            allowed_root.display()
        ));
    }

    Ok(resolved.display().to_string())
}

fn resolve_allowed_root(scan_path: &Path, config_dir: &Path) -> PathBuf {
    let scan_root = resolve_scan_root(scan_path);
    let config_dir = resolve_path_for_boundary(config_dir);

    if scan_root.starts_with(&config_dir) {
        config_dir
    } else {
        scan_root
    }
}

fn resolve_scan_root(scan_path: &Path) -> PathBuf {
    let scan_root = resolve_path_for_boundary(scan_path);
    if scan_root.is_file() {
        scan_root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        scan_root
    }
}

fn resolve_path_for_boundary(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    let absolute = absolutize_path(path);
    for ancestor in absolute.ancestors() {
        if let Ok(canonical_ancestor) = ancestor.canonicalize() {
            let suffix = absolute
                .strip_prefix(ancestor)
                .unwrap_or_else(|_| Path::new(""));
            return normalize_path(&canonical_ancestor.join(suffix));
        }
    }

    normalize_path(&absolute)
}

fn absolutize_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn write_config(dir: &Path, relative_path: &str, content: &str) -> PathBuf {
        let path = dir.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("failed to create config directory");
        }
        fs::write(&path, content).expect("failed to write config");
        path
    }

    #[test]
    fn load_for_scan_rejects_parent_traversal_in_config_paths() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  rules: ../../../etc/passwd\n",
        );

        let err = load_for_scan(repo.path(), None).expect_err("expected traversal to fail");

        assert!(err.contains("scan.rules"), "unexpected error: {err}");
        assert!(
            err.contains("escapes the project root"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_for_scan_rejects_absolute_paths_outside_project_root() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let outside = TempDir::new().expect("failed to create outside temp dir");
        let outside_rules = outside.path().join("rules.yml");
        fs::write(&outside_rules, "rules: []\n").expect("failed to write outside file");

        write_config(
            repo.path(),
            ".foxguard.yml",
            &format!("scan:\n  rules: {}\n", outside_rules.display()),
        );

        let err = load_for_scan(repo.path(), None).expect_err("expected absolute path to fail");

        assert!(err.contains("scan.rules"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn load_for_scan_rejects_symlink_escapes() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let outside = TempDir::new().expect("failed to create outside temp dir");
        let outside_baseline = outside.path().join("baseline.json");
        fs::write(&outside_baseline, "[]\n").expect("failed to write outside baseline");
        symlink(&outside_baseline, repo.path().join("baseline.json"))
            .expect("failed to create symlink");

        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  baseline: baseline.json\n",
        );

        let err = load_for_scan(repo.path(), None).expect_err("expected symlink escape to fail");

        assert!(err.contains("scan.baseline"), "unexpected error: {err}");
    }

    #[test]
    fn load_for_scan_allows_paths_within_scan_root_for_nested_explicit_config() {
        let repo = TempDir::new().expect("failed to create temp dir");
        fs::create_dir_all(repo.path().join("fixtures")).expect("failed to create fixture dir");
        let config = write_config(
            repo.path(),
            "config/foxguard.yml",
            "secrets:\n  exclude_paths:\n    - ../fixtures\n",
        );

        let loaded = load_for_scan(repo.path(), Some(config.to_str().expect("non-utf8 path")))
            .expect("failed to load config")
            .expect("expected config");
        let expected = resolve_path_for_boundary(&repo.path().join("fixtures"));

        assert_eq!(
            loaded.secrets.exclude_paths,
            vec![expected.display().to_string()]
        );
    }
}
