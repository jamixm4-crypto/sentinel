use colored::*;
use sentinel_core::{Lang, ScanResult, Severity, Verdict};

pub fn print_terminal_summary(result: &ScanResult, lang: Lang) {
    println!();
    println!(
        "  {} {}",
        "🔍 Sentinel".bold().cyan(),
        format!("v{} — Surveillance Software Detector", env!("CARGO_PKG_VERSION")).dimmed()
    );
    println!();

    // Verdict Banner
    match result.verdict {
        Verdict::Clean => {
            println!(
                "  {} {}",
                "✔".bold().green(),
                match lang {
                    Lang::Ru => "Следящее ПО не обнаружено".bold().green(),
                    Lang::En => "No Surveillance Software Detected".bold().green(),
                }
            );
        }
        Verdict::ReviewRecommended => {
            println!(
                "  {} {}",
                "▲".bold().yellow(),
                match lang {
                    Lang::Ru => "Рекомендуется ручная проверка находок".bold().yellow(),
                    Lang::En => "Review Recommended — Verify Dual-Use Software".bold().yellow(),
                }
            );
        }
        Verdict::SurveillanceLikely => {
            println!(
                "  {} {}",
                "✖".bold().red(),
                match lang {
                    Lang::Ru => "ВНИМАНИЕ: Вероятно обнаружено следящее ПО!".bold().red(),
                    Lang::En => "WARNING: Surveillance Software Likely Detected!".bold().red(),
                }
            );
        }
    }

    println!();
    println!(
        "  Platform: {} {} ({}) | Privilege: {:?}",
        result.platform.os_name, result.platform.os_version, result.platform.architecture, result.platform.privilege_level
    );
    println!(
        "  Scan duration: {:.2}s | Inspected processes: {}",
        result.scan_duration.as_secs_f32(),
        result.total_inspected_processes
    );

    if !result.skipped_checks.is_empty() {
        println!(
            "  {} {} check(s) skipped due to privilege requirements",
            "⚠".yellow(),
            result.skipped_checks.len()
        );
    }

    println!("  {}", "─".repeat(60).dimmed());

    if result.findings.is_empty() {
        println!("  No suspicious or surveillance items identified.");
    } else {
        for finding in &result.findings {
            let sev_badge = match finding.severity {
                Severity::Critical => "[CRITICAL]".bold().red(),
                Severity::High => "[HIGH]    ".bold().red(),
                Severity::Medium => "[MEDIUM]  ".bold().yellow(),
                Severity::Low => "[LOW]     ".blue(),
                Severity::Info => "[INFO]    ".cyan(),
            };

            let policy_str = finding.removal_policy.label_en();

            println!(
                "  {} {} {} (Confidence: {:.0}%)",
                sev_badge,
                finding.category.icon(),
                finding.name.bold(),
                finding.confidence.score * 100.0
            );
            println!(
                "     Category: {} | Policy: {}",
                finding.category.name_en().dimmed(),
                policy_str.dimmed()
            );
            println!("     Evidence count: {}", finding.evidence.len());
            println!();
        }
    }

    println!("  {}", "─".repeat(60).dimmed());
}
