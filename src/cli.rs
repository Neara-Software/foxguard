use clap::Parser;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum SeverityFilter {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Parser, Debug)]
#[command(
    name = "foxguard",
    about = "Fast security linting for modern codebases",
    version
)]
pub struct Cli {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Path to Semgrep YAML rule file or directory
    #[arg(short, long)]
    pub rules: Option<String>,
}

impl SeverityFilter {
    pub fn to_severity(&self) -> crate::Severity {
        match self {
            SeverityFilter::Low => crate::Severity::Low,
            SeverityFilter::Medium => crate::Severity::Medium,
            SeverityFilter::High => crate::Severity::High,
            SeverityFilter::Critical => crate::Severity::Critical,
        }
    }
}
