use crate::{Finding, Severity};
use colored::Colorize;

pub fn print_findings(findings: &[Finding], files_scanned: usize, duration: std::time::Duration) {
    if findings.is_empty() {
        if files_scanned > 0 {
            println!(
                "{}  Scanned {} files in {:.2}s",
                "No security issues found.".green().bold(),
                files_scanned.to_string().bold(),
                duration.as_secs_f64(),
            );
        } else {
            println!("{}", "No security issues found.".green().bold());
        }
        return;
    }

    let mut current_file = String::new();

    for f in findings {
        if f.file != current_file {
            current_file = f.file.clone();
            println!("\n{}", current_file.bold().underline());
        }

        let severity_str = match f.severity {
            Severity::Critical => format!(" {} ", "CRITICAL").on_red().white().bold(),
            Severity::High => format!(" {} ", "HIGH").on_red().white().bold(),
            Severity::Medium => format!(" {} ", "MEDIUM").on_yellow().black().bold(),
            Severity::Low => format!(" {} ", "LOW").on_blue().white().bold(),
        };

        let cwe = f
            .cwe
            .as_ref()
            .map(|c| format!(" ({})", c))
            .unwrap_or_default();

        println!(
            "  {}:{} {} {}{} {}",
            f.line.to_string().dimmed(),
            f.column.to_string().dimmed(),
            severity_str,
            f.rule_id.cyan(),
            cwe.dimmed(),
            f.description,
        );

        if !f.snippet.is_empty() {
            for line in f.snippet.lines() {
                println!("    {}", line.dimmed());
            }
        }
    }

    // Summary
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    let stats = if files_scanned > 0 {
        format!(
            " in {} files ({:.2}s)",
            files_scanned,
            duration.as_secs_f64()
        )
    } else {
        String::new()
    };

    println!(
        "\n{} {}{}: {} critical, {} high, {} medium, {} low",
        "WARNING".yellow(),
        format!("{} issues", findings.len()).bold(),
        stats.dimmed(),
        critical.to_string().red().bold(),
        high.to_string().red(),
        medium.to_string().yellow(),
        low.to_string().blue(),
    );
}
