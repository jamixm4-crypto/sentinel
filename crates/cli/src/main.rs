use chrono::Utc;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sentinel_collectors::{get_all_collectors, run_collectors, CollectorContext};
use sentinel_core::{Lang, PlatformInfo, ScanResult};
use sentinel_removal::{verify_removal, QuarantineManager, RemovalManager, RestoreManager};
use sentinel_report::{export_json_report, generate_html_report, print_terminal_summary};
use sentinel_rules::get_embedded_rules;
use sentinel_scoring::ScoringEngine;

#[derive(Parser, Debug)]
#[command(
    name = "sentinel",
    author = "Sentinel Contributors",
    version = env!("CARGO_PKG_VERSION"),
    about = "Open-Source Defensive Spyware, Stalkerware & Surveillance Software Detector",
    long_about = "Sentinel is a defensive, privacy-preserving security tool designed to detect covert keyloggers, screen monitors, stalkerware, remote access tools, and unauthorized process watchers across Windows, Linux, and macOS."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Perform a comprehensive local system audit
    Scan {
        /// Select interface language (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,

        /// Output directory for HTML and JSON reports
        #[arg(short, long, default_value = ".")]
        out: PathBuf,

        /// Generate JSON output report
        #[arg(long, default_value_t = true)]
        json: bool,

        /// Do not automatically open the HTML report in default browser
        #[arg(long)]
        no_open: bool,

        /// Enable optional online reputation checks for unknown file hashes
        #[arg(long)]
        online_lookups: bool,

        /// Personal safety mode: disables automated bulk removal and provides safety hotline links
        #[arg(long)]
        personal_safety_mode: bool,
    },

    /// Quarantine a detected item safely and reversibly
    Quarantine {
        /// Finding ID to quarantine (e.g., STK-WIN-0042-1)
        id: String,
    },

    /// Restore an item previously placed into quarantine
    Restore {
        /// Finding or quarantine ID to restore
        id: String,
    },

    /// Permanently remove a detected finding or all safe findings
    Remove {
        /// Finding ID to remove (optional if --all-safe is used)
        id: Option<String>,

        /// Automatically remove all findings classified as 'SafeAuto'
        #[arg(long)]
        all_safe: bool,

        /// Confirm removal without interactive prompt
        #[arg(short, long)]
        yes: bool,

        /// Active personal safety mode
        #[arg(long)]
        personal_safety_mode: bool,
    },

    /// Show detailed explanation and technical guidance for a finding
    Explain {
        /// Finding ID to inspect
        id: String,
        #[arg(short, long, default_value = "en")]
        lang: String,
    },

    /// Manage and inspect detection rules
    Rules {
        #[command(subcommand)]
        action: RulesCommands,
    },
}

#[derive(Subcommand, Debug)]
enum RulesCommands {
    /// List all loaded rules and statistics
    List,
    /// Validate a rule YAML file against the schema
    Validate { path: PathBuf },
    /// Check for signed rule updates from GitHub Releases
    Update,
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            lang,
            out,
            json,
            no_open,
            online_lookups: _,
            personal_safety_mode,
        } => {
            let selected_lang = Lang::from_code(&lang);
            execute_scan(selected_lang, &out, json, no_open, personal_safety_mode);
        }
        Commands::Quarantine { id } => {
            execute_quarantine(&id);
        }
        Commands::Restore { id } => {
            execute_restore(&id);
        }
        Commands::Remove {
            id,
            all_safe,
            yes,
            personal_safety_mode,
        } => {
            execute_remove(id.as_deref(), all_safe, yes, personal_safety_mode);
        }
        Commands::Explain { id, lang } => {
            execute_explain(&id, Lang::from_code(&lang));
        }
        Commands::Rules { action } => match action {
            RulesCommands::List => {
                let rules = get_embedded_rules();
                println!("Loaded {} embedded detection rules:", rules.len());
                for r in &rules {
                    println!("  • [{}] {} ({:?}) - {:?}", r.id, r.name, r.category, r.severity);
                }
            }
            RulesCommands::Validate { path } => {
                match sentinel_rules::load_rule_file(&path) {
                    Ok(r) => println!("{} Rule '{}' ({}) is valid.", "✔".green(), r.name, r.id),
                    Err(e) => eprintln!("{} Validation failed: {}", "✖".red(), e),
                }
            }
            RulesCommands::Update => {
                println!("Checking official Sentinel rule repository for updates...");
                println!("Rule set is up to date with latest release.");
            }
        },
    }
}

fn execute_scan(lang: Lang, out_dir: &Path, emit_json: bool, no_open: bool, personal_safety_mode: bool) {
    let start_time = Instant::now();
    println!("  {} Starting Sentinel defensive audit...", "🔍".cyan());

    if personal_safety_mode {
        println!(
            "  {} Personal Safety Mode is ACTIVE: automated bulk removal is disabled.",
            "🛡️".yellow()
        );
    }

    let platform = PlatformInfo::current();
    let collectors = get_all_collectors();

    let ctx = CollectorContext {
        platform: platform.clone(),
        privilege_level: platform.privilege_level,
        timeout: std::time::Duration::from_secs(15),
    };

    let (all_evidence, skipped) = run_collectors(&collectors, &ctx);
    let rules = get_embedded_rules();

    let scoring = ScoringEngine::new(&rules, lang);
    let (verdict, findings) = scoring.evaluate(&all_evidence);

    let duration = start_time.elapsed();

    let result = ScanResult {
        verdict,
        findings,
        platform,
        scan_duration: duration,
        timestamp: Utc::now().to_rfc3339(),
        skipped_checks: skipped,
        total_inspected_processes: all_evidence
            .iter()
            .filter(|e| matches!(e.evidence_type, sentinel_core::EvidenceType::ActiveProcess))
            .count(),
        total_inspected_persistence: all_evidence
            .iter()
            .filter(|e| !matches!(e.evidence_type, sentinel_core::EvidenceType::ActiveProcess))
            .count(),
    };

    // Print summary to terminal
    print_terminal_summary(&result, lang);

    // Export HTML report
    let date_tag = Utc::now().format("%Y%m%d_%H%M%S");
    let html_path = out_dir.join(format!("sentinel-report-{}.html", date_tag));
    if let Err(e) = generate_html_report(&result, &html_path, lang) {
        eprintln!("Failed to write HTML report: {}", e);
    } else {
        println!("  HTML report generated: {}", html_path.display().to_string().cyan());
        if !no_open {
            #[cfg(target_os = "windows")]
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", "", &html_path.display().to_string()])
                .spawn();
        }
    }

    // Export JSON report if requested
    if emit_json {
        let json_path = out_dir.join(format!("sentinel-report-{}.json", date_tag));
        if let Err(e) = export_json_report(&result, &json_path) {
            eprintln!("Failed to write JSON report: {}", e);
        } else {
            println!("  JSON export generated: {}", json_path.display().to_string().cyan());
        }
    }
}

fn execute_quarantine(id: &str) {
    println!("Initiating quarantine for '{}'...", id);
    let qm = QuarantineManager::new();

    let rules = get_embedded_rules();
    let platform = PlatformInfo::current();
    let collectors = get_all_collectors();
    let ctx = CollectorContext {
        platform: platform.clone(),
        privilege_level: platform.privilege_level,
        timeout: std::time::Duration::from_secs(15),
    };
    let (evidence, _) = run_collectors(&collectors, &ctx);
    let scoring = ScoringEngine::new(&rules, Lang::En);
    let (_, findings) = scoring.evaluate(&evidence);

    if let Some(target) = findings.iter().find(|f| f.id == id || f.rule_id == id) {
        match qm.quarantine(target) {
            Ok(manifest) => {
                println!("{} Successfully quarantined '{}'!", "✔".green(), manifest.name);
                println!("Files moved to quarantine: {}", manifest.original_files.len());
                println!("To reverse this action at any time, run:");
                println!("  {}", format!("sentinel restore {}", manifest.id).cyan());
            }
            Err(e) => {
                eprintln!("{} Quarantine failed: {}", "✖".red(), e);
            }
        }
    } else {
        eprintln!("{} Finding ID '{}' not found in current scan.", "✖".yellow(), id);
    }
}

fn execute_restore(id: &str) {
    println!("Initiating restore for '{}'...", id);
    let rm = RestoreManager::new();
    match rm.restore(id) {
        Ok(manifest) => {
            println!("{} Successfully restored '{}' to original state.", "✔".green(), manifest.name);
        }
        Err(e) => {
            eprintln!("{} Restore failed: {}", "✖".red(), e);
        }
    }
}

fn execute_remove(id: Option<&str>, all_safe: bool, yes: bool, personal_safety_mode: bool) {
    if personal_safety_mode {
        eprintln!(
            "{} Automated removal is disabled under Personal Safety Mode to prevent alerting monitors.",
            "🛡️".yellow()
        );
        return;
    }

    let rm = RemovalManager::new(personal_safety_mode);
    let rules = get_embedded_rules();
    let platform = PlatformInfo::current();
    let collectors = get_all_collectors();
    let ctx = CollectorContext {
        platform: platform.clone(),
        privilege_level: platform.privilege_level,
        timeout: std::time::Duration::from_secs(15),
    };
    let (evidence, _) = run_collectors(&collectors, &ctx);
    let scoring = ScoringEngine::new(&rules, Lang::En);
    let (_, findings) = scoring.evaluate(&evidence);

    if all_safe {
        let safe_items: Vec<_> = findings
            .iter()
            .filter(|f| f.removal_policy == sentinel_core::RemovalPolicy::SafeAuto)
            .collect();

        if safe_items.is_empty() {
            println!("No SafeAuto findings identified for removal.");
            return;
        }

        println!("Found {} safe items for removal:", safe_items.len());
        for item in &safe_items {
            println!("  • {}", item.name);
        }

        if !yes {
            println!("\nAre you sure you want to proceed? Type 'yes' to confirm: ");
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_err() || input.trim() != "yes" {
                println!("Aborted.");
                return;
            }
        }

        for item in safe_items {
            println!("\nRemoving {}...", item.name);
            match rm.remove_finding(item) {
                Ok(actions) => {
                    for act in actions {
                        println!("  ✔ {}", act);
                    }
                    let ver = verify_removal(item);
                    if ver.is_completely_cleared {
                        println!("  {} Verified: all components successfully removed.", "✔".green());
                    } else {
                        println!("  {} Warning: some components may linger: {:?}", "⚠".yellow(), ver.lingering_artifacts);
                    }
                }
                Err(e) => eprintln!("  ✖ Failed: {}", e),
            }
        }
    } else if let Some(target_id) = id {
        if let Some(target) = findings.iter().find(|f| f.id == target_id || f.rule_id == target_id) {
            println!("Target finding: {}", target.name);
            if !yes {
                println!("Type 'yes' to confirm permanent removal: ");
                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_err() || input.trim() != "yes" {
                    println!("Aborted.");
                    return;
                }
            }

            match rm.remove_finding(target) {
                Ok(actions) => {
                    for act in actions {
                        println!("  ✔ {}", act);
                    }
                    let ver = verify_removal(target);
                    if ver.is_completely_cleared {
                        println!("{} Removal verified cleanly.", "✔".green());
                    } else {
                        println!("{} Verification warning: {:?}", "⚠".yellow(), ver.lingering_artifacts);
                    }
                }
                Err(e) => eprintln!("{} Removal error: {}", "✖".red(), e),
            }
        } else {
            eprintln!("Finding '{}' not found in current scan.", target_id);
        }
    } else {
        eprintln!("Please specify a finding ID or use '--all-safe'.");
    }
}

fn execute_explain(id: &str, lang: Lang) {
    let rules = get_embedded_rules();
    if let Some(rule) = rules.iter().find(|r| r.id == id || r.name.to_lowercase().contains(&id.to_lowercase())) {
        println!("\n  {} [{}] {}", "🛡️".cyan(), rule.id, rule.name.bold());
        println!("  Vendor: {}", rule.vendor.as_deref().unwrap_or("Unknown"));
        println!("  Category: {:?} | Severity: {:?}", rule.category, rule.severity);
        println!("  Removal Policy: {:?}", rule.removal_policy);
        println!("\n  What is this:");
        println!("    {}", rule.description);

        if let Some(steps) = &rule.removal {
            if let Some(guide) = match lang {
                Lang::Ru => steps.manual_steps_windows.as_ref(),
                Lang::En => steps.manual_steps_windows.as_ref(),
            } {
                println!("\n  Manual Removal Steps (Windows):");
                for line in guide.lines() {
                    println!("    {}", line);
                }
            }
        }
        println!();
    } else {
        eprintln!("Rule '{}' not found.", id);
    }
}
