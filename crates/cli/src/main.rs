use chrono::Utc;
use clap::{Parser, Subcommand};
use colored::*;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sentinel_collectors::{get_all_collectors, run_collectors, CollectorContext};
use sentinel_core::{Lang, PlatformInfo, ScanResult};
use sentinel_removal::{get_sentinel_data_dir, verify_removal, QuarantineManager, RemovalManager, RestoreManager};
use sentinel_report::{export_json_report, generate_html_report, print_terminal_summary};
use sentinel_rules::get_embedded_rules;
use sentinel_scoring::ScoringEngine;

#[derive(Parser, Debug)]
#[command(
    name = "sentinel",
    author = "Sentinel Contributors",
    version = env!("CARGO_PKG_VERSION"),
    about = "Defensive, Privacy-Preserving Stalkerware & Surveillance Software Detector",
    long_about = "Sentinel is an open-source, read-only-by-default defensive tool engineered to detect covert keyloggers, screen recording spyware, stalkerware, unauthorized remote access tools, and watchdog monitors across Windows, Linux, and macOS."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Perform a system audit or forensic disk inspection
    Scan {
        /// Select interface language (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,

        /// Output directory for reports (default: current directory)
        #[arg(short, long, default_value = ".")]
        out: PathBuf,

        /// Generate JSON output report
        #[arg(long, default_value_t = true)]
        json: bool,

        /// Output format: terminal | json | ndjson | ecs | html
        #[arg(long, default_value = "terminal")]
        format: String,

        /// Suppress non-essential output, spinners, and headers
        #[arg(short, long)]
        quiet: bool,

        /// Display verbose diagnostic collection details and collector traces
        #[arg(short, long)]
        verbose: bool,

        /// Forensic mode: scan an offline directory or mounted disk image instead of live system
        #[arg(long)]
        scan_path: Option<PathBuf>,

        /// Directory containing custom or offline YAML rules to load alongside embedded rules
        #[arg(long)]
        rules_dir: Option<PathBuf>,

        /// Path to custom user allowlist file (JSON list of rule IDs or binary names)
        #[arg(long)]
        allowlist: Option<PathBuf>,

        /// In-memory terminal output only; do not write any report files to local disk
        #[arg(long)]
        stdout_only: bool,

        /// Do not automatically open the HTML report in default browser
        #[arg(long)]
        no_open: bool,

        /// Enable optional online reputation checks for unknown file hashes
        #[arg(long)]
        online_lookups: bool,

        /// Personal safety mode: disables modification and suppresses local disk artifacts
        #[arg(long)]
        personal_safety_mode: bool,
    },

    /// Quarantine a detected item safely and reversibly
    Quarantine {
        /// Finding ID to quarantine (e.g., STK-WIN-0042-1)
        id: String,

        /// Execute quarantine (defaults to false for safe dry-run)
        #[arg(long)]
        execute: bool,

        /// Active personal safety mode
        #[arg(long)]
        personal_safety_mode: bool,

        /// Force execution in Personal Safety Mode acknowledging physical risks
        #[arg(long)]
        force_risk_acknowledged: bool,
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

        /// Target all findings classified as 'SafeAuto'
        #[arg(long)]
        all_safe: bool,

        /// Execute removal (defaults to false for safe dry-run)
        #[arg(long)]
        execute: bool,

        /// Confirm removal without interactive prompt
        #[arg(short, long)]
        yes: bool,

        /// Active personal safety mode
        #[arg(long)]
        personal_safety_mode: bool,

        /// Force execution in Personal Safety Mode acknowledging physical risks
        #[arg(long)]
        force_risk_acknowledged: bool,
    },

    /// Manage user-defined allowlist to suppress known benign alerts
    Allow {
        #[command(subcommand)]
        action: AllowCommands,
    },

    /// Show detailed explanation and technical guidance for a finding
    Explain {
        /// Finding ID or rule ID to inspect
        id: String,
        #[arg(short, long, default_value = "en")]
        lang: String,
    },

    /// Manage and inspect detection rules
    Rules {
        #[command(subcommand)]
        action: RulesCommands,
    },

    /// Completely uninstall Sentinel, delete quarantine vault, remove all audit reports and config files
    Purge {
        /// Suppress interactive confirmation prompt
        #[arg(short, long)]
        yes: bool,

        /// Path to custom directory to clean reports from (defaults to current directory)
        #[arg(long, default_value = ".")]
        reports_dir: PathBuf,

        /// Only delete audit reports (sentinel-report-*), keeping binary and settings
        #[arg(long)]
        reports_only: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AllowCommands {
    /// List all entries currently in the user allowlist
    List,
    /// Add a rule ID, process name, or C2 domain to user allowlist
    Add { entry: String },
    /// Remove an entry from user allowlist
    Remove { entry: String },
}

#[derive(Subcommand, Debug)]
enum RulesCommands {
    /// List all loaded rules and statistics
    List,
    /// Validate a rule YAML file against the schema
    Validate { path: PathBuf },
    /// Import offline rule packages or check for updates
    Update {
        /// Import rules from a local directory or file
        #[arg(long)]
        from: Option<PathBuf>,
    },
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            lang,
            out,
            json,
            format,
            quiet,
            verbose,
            scan_path,
            rules_dir,
            allowlist,
            stdout_only,
            no_open,
            online_lookups: _,
            personal_safety_mode,
        } => {
            let selected_lang = Lang::from_code(&lang);
            execute_scan(
                selected_lang,
                &out,
                json,
                &format,
                quiet,
                verbose,
                scan_path.as_deref(),
                rules_dir.as_deref(),
                allowlist.as_deref(),
                stdout_only,
                no_open,
                personal_safety_mode,
            );
        }
        Commands::Quarantine {
            id,
            execute,
            personal_safety_mode,
            force_risk_acknowledged,
        } => {
            execute_quarantine(&id, execute, personal_safety_mode, force_risk_acknowledged);
        }
        Commands::Restore { id } => {
            execute_restore(&id);
        }
        Commands::Remove {
            id,
            all_safe,
            execute,
            yes,
            personal_safety_mode,
            force_risk_acknowledged,
        } => {
            execute_remove(
                id.as_deref(),
                all_safe,
                execute,
                yes,
                personal_safety_mode,
                force_risk_acknowledged,
            );
        }
        Commands::Allow { action } => match action {
            AllowCommands::List => {
                let list = load_user_allowlist_entries();
                if list.is_empty() {
                    println!("User allowlist is empty. Add entries with 'sentinel allow add <id_or_name>'.");
                } else {
                    println!("User allowlist entries ({}):", list.len());
                    for item in list {
                        println!("  • {}", item);
                    }
                }
            }
            AllowCommands::Add { entry } => {
                let mut list = load_user_allowlist_entries();
                let clean = entry.trim().to_lowercase();
                list.insert(clean.clone());
                if let Err(e) = save_user_allowlist_entries(&list) {
                    eprintln!("{} Failed to save allowlist: {}", "✖".red(), e);
                } else {
                    println!("{} Added '{}' to user allowlist.", "✔".green(), clean);
                }
            }
            AllowCommands::Remove { entry } => {
                let mut list = load_user_allowlist_entries();
                let clean = entry.trim().to_lowercase();
                if list.remove(&clean) {
                    if let Err(e) = save_user_allowlist_entries(&list) {
                        eprintln!("{} Failed to save allowlist: {}", "✖".red(), e);
                    } else {
                        println!("{} Removed '{}' from user allowlist.", "✔".green(), clean);
                    }
                } else {
                    println!("'{}' not found in user allowlist.", clean);
                }
            }
        },
        Commands::Explain { id, lang } => {
            execute_explain(&id, Lang::from_code(&lang));
        }
        Commands::Rules { action } => match action {
            RulesCommands::List => {
                let rules = load_all_rules(None);
                println!("Loaded {} detection rules (embedded + local):", rules.len());
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
            RulesCommands::Update { from } => {
                if let Some(src) = from {
                    println!("Importing rules / threat indicators from '{}'...", src.display());
                    let sentinel_dir = get_sentinel_data_dir();
                    let target_dir = sentinel_dir.join("rules");
                    if let Err(e) = std::fs::create_dir_all(&target_dir) {
                        eprintln!("{} Failed to create rules directory: {}", "✖".red(), e);
                        return;
                    }
                    if src.is_dir() {
                        let mut count = 0;
                        if let Ok(entries) = std::fs::read_dir(&src) {
                            for entry in entries.filter_map(Result::ok) {
                                let p = entry.path();
                                if p.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
                                    if let Some(name) = p.file_name() {
                                        let dest = target_dir.join(name);
                                        let _ = std::fs::copy(&p, dest);
                                        count += 1;
                                    }
                                } else if p.file_name().map_or(false, |n| n == "c2_domains.txt") {
                                    let dest = sentinel_dir.join("c2_domains.txt");
                                    let _ = std::fs::copy(&p, dest);
                                    println!("{} Imported offline C2 domains list into '{}'.", "✔".green(), sentinel_dir.join("c2_domains.txt").display());
                                }
                            }
                        }
                        println!("{} Successfully imported {} rules into '{}'.", "✔".green(), count, target_dir.display());
                    } else if src.is_file() {
                        let ext = src.extension().and_then(|s| s.to_str()).unwrap_or("");
                        if ext == "txt" {
                            let dest = sentinel_dir.join("c2_domains.txt");
                            if let Err(e) = std::fs::copy(&src, &dest) {
                                eprintln!("{} Failed to copy C2 domains file: {}", "✖".red(), e);
                            } else {
                                println!("{} Successfully updated offline C2 domain feed in '{}'.", "✔".green(), dest.display());
                            }
                        } else if ext == "yml" || ext == "yaml" {
                            if let Some(name) = src.file_name() {
                                let dest = target_dir.join(name);
                                if let Err(e) = std::fs::copy(&src, dest) {
                                    eprintln!("{} Failed to copy rule file: {}", "✖".red(), e);
                                } else {
                                    println!("{} Successfully imported rule into '{}'.", "✔".green(), target_dir.display());
                                }
                            }
                        } else {
                            eprintln!("{} Unrecognized file format. Expected .yml, .yaml, or .txt.", "✖".red());
                        }
                    }
                } else {
                    println!("Rule set is up to date (100+ embedded rules, 280+ C2 domains).");
                    println!("To import external rules or C2 domain feeds offline, run:");
                    println!("  {}", "sentinel rules update --from <path/to/rules_or_c2.txt>".cyan());
                }
            }
        },
        Commands::Purge {
            yes,
            reports_dir,
            reports_only,
        } => {
            execute_purge(yes, &reports_dir, reports_only);
        }
    }
}

fn execute_scan(
    lang: Lang,
    out_dir: &Path,
    emit_json: bool,
    format_opt: &str,
    quiet: bool,
    verbose: bool,
    scan_path: Option<&Path>,
    rules_dir: Option<&Path>,
    allowlist_path: Option<&Path>,
    stdout_only: bool,
    no_open: bool,
    personal_safety_mode: bool,
) {
    let start_time = Instant::now();
    let rules = load_all_rules(rules_dir);

    let spinner = if !quiet && format_opt == "terminal" {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
                .template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| indicatif::ProgressStyle::default_spinner()),
        );
        pb.set_message("Conducting surveillance audit across processes, persistence, and network hooks...");
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    // Collect evidence (Forensic offline scan OR live OS collectors)
    let (all_evidence, skipped) = if let Some(target) = scan_path {
        (run_offline_disk_scan(target, &rules), Vec::new())
    } else {
        if !quiet && format_opt == "terminal" && spinner.is_none() {
            println!("  {} Starting Sentinel defensive audit...", "🔍".cyan());
        }
        let platform = PlatformInfo::current();
        let collectors = get_all_collectors();
        let ctx = CollectorContext {
            platform,
            privilege_level: PlatformInfo::current().privilege_level,
            timeout: std::time::Duration::from_secs(15),
        };
        run_collectors(&collectors, &ctx)
    };

    // User allowlist resolution
    let user_allowlist = if let Some(custom_allow) = allowlist_path {
        if let Ok(content) = std::fs::read_to_string(custom_allow) {
            serde_json::from_str::<Vec<String>>(&content)
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect()
        } else {
            load_user_allowlist_entries()
        }
    } else {
        load_user_allowlist_entries()
    };

    let custom_c2 = load_custom_c2_domains();
    let scoring = ScoringEngine::new(&rules, lang)
        .with_allowlist(user_allowlist)
        .with_custom_c2(custom_c2);
    let (verdict, findings) = scoring.evaluate(&all_evidence);
    let duration = start_time.elapsed();

    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    let result = ScanResult {
        verdict,
        findings,
        platform: PlatformInfo::current(),
        scan_duration: duration,
        timestamp: Utc::now().to_rfc3339(),
        skipped_checks: skipped.clone(),
        total_inspected_processes: all_evidence
            .iter()
            .filter(|e| matches!(e.evidence_type, sentinel_core::EvidenceType::ActiveProcess))
            .count(),
        total_inspected_persistence: all_evidence
            .iter()
            .filter(|e| !matches!(e.evidence_type, sentinel_core::EvidenceType::ActiveProcess))
            .count(),
    };

    if verbose {
        println!("  {} Diagnostic scan metrics:", "ℹ️".blue());
        println!("    • Evidence records collected: {}", all_evidence.len());
        println!("    • Detection rules evaluated: {}", rules.len());
        println!("    • Scan execution time: {:?}", duration);
        if !skipped.is_empty() {
            println!("    • Skipped checks (insufficient privilege):");
            for sc in &skipped {
                println!("      - {}: {}", sc.collector, sc.description);
            }
        }
        println!();
    }

    // ECS JSON output for Elastic / SIEM ingestion
    if format_opt == "ecs" {
        print!("{}", sentinel_report::export_ecs_ndjson(&result));
        return;
    }

    // NDJSON output for SIEM ingestion (Elasticsearch, Splunk, Wazuh)
    if format_opt == "ndjson" {
        for f in &result.findings {
            if let Ok(line) = serde_json::to_string(f) {
                println!("{}", line);
            }
        }
        return;
    }

    if format_opt == "json" && stdout_only {
        if let Ok(s) = serde_json::to_string_pretty(&result) {
            println!("{}", s);
        }
        return;
    }

    // Terminal Summary
    if quiet {
        if result.findings.is_empty() {
            println!("✔ Clean: No stalkerware or surveillance indicators detected.");
        } else {
            print_terminal_summary(&result, lang);
        }
    } else {
        print_terminal_summary(&result, lang);
    }

    // Personal Safety Notice & Residual Traces Warning
    if personal_safety_mode {
        println!();
        println!(
            "  {} {}",
            "🛡️".yellow(),
            "PERSONAL SAFETY MODE ACTIVE".bold().yellow()
        );
        println!("  • In-memory execution: zero report files were saved to local disk.");
        println!("  • Destructive removal and quarantine actions are strictly blocked.");
        println!("  • Browser auto-launch suppressed to prevent leaving history or cache.");
        println!("  • CAUTION ON FORENSIC TRACES:");
        println!("    - Windows Prefetch, BAM/DAM, and command shells record executions.");
        println!("    - Seek support from a secure, unmonitored device whenever possible.");
        println!("    - Resources: https://stopstalkerware.org | https://lila.help");
        return;
    }

    if stdout_only {
        return;
    }

    // Write HTML Report
    let date_tag = Utc::now().format("%Y%m%d_%H%M%S");
    let html_path = out_dir.join(format!("sentinel-report-{}.html", date_tag));
    if let Err(e) = generate_html_report(&result, &html_path, lang) {
        eprintln!("Failed to write HTML report: {}", e);
    } else {
        let abs_html = if html_path.is_relative() {
            std::env::current_dir().unwrap_or_default().join(&html_path)
        } else {
            html_path.clone()
        };
        println!("  HTML report generated: {}", abs_html.display().to_string().cyan());
        if !no_open {
            #[cfg(target_os = "windows")]
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", "", &abs_html.display().to_string()])
                .spawn();
            #[cfg(target_os = "macos")]
            let _ = std::process::Command::new("open")
                .arg(&abs_html)
                .spawn();
            #[cfg(target_os = "linux")]
            let _ = std::process::Command::new("xdg-open")
                .arg(&abs_html)
                .spawn();
        }
    }

    // Write JSON Report
    if emit_json {
        let json_path = out_dir.join(format!("sentinel-report-{}.json", date_tag));
        if let Err(e) = export_json_report(&result, &json_path) {
            eprintln!("Failed to write JSON report: {}", e);
        } else {
            println!("  JSON export generated: {}", json_path.display().to_string().cyan());
        }
    }
}

fn execute_quarantine(
    id: &str,
    execute: bool,
    personal_safety_mode: bool,
    force_risk_acknowledged: bool,
) {
    if personal_safety_mode && !force_risk_acknowledged {
        eprintln!(
            "\n  {} {}\n  Quarantine is strictly blocked under Personal Safety Mode.\n  Terminating services or moving binaries alerts surveillance operators.\n  To override if you have an established safety plan, pass: --force-risk-acknowledged\n",
            "🛡️".yellow(),
            "ACTION BLOCKED BY PERSONAL SAFETY POLICY".bold().yellow()
        );
        return;
    }

    let qm = QuarantineManager::new(personal_safety_mode && !force_risk_acknowledged);
    let rules = load_all_rules(None);
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
        if !execute {
            println!("\n  {} {}", "🔍".cyan(), "[DRY RUN] Simulating quarantine (no changes made):".bold());
            match qm.dry_run(target) {
                Ok(planned) => {
                    for act in planned {
                        println!("    • {}", act);
                    }
                    println!("\n  To execute this quarantine action, rerun with: {}", "--execute".green());
                }
                Err(e) => eprintln!("  ✖ Dry-run failed: {}", e),
            }
            return;
        }

        println!("Executing quarantine for '{}'...", id);
        match qm.quarantine(target) {
            Ok(manifest) => {
                println!("{} Successfully quarantined '{}'!", "✔".green(), manifest.name);
                println!("Files moved to vault: {}", manifest.original_files.len());
                println!("To reverse this action at any time, run:");
                println!("  {}", format!("sentinel restore {}", manifest.id).cyan());
            }
            Err(e) => eprintln!("{} Quarantine failed: {}", "✖".red(), e),
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
        Err(e) => eprintln!("{} Restore failed: {}", "✖".red(), e),
    }
}

fn execute_remove(
    id: Option<&str>,
    all_safe: bool,
    execute: bool,
    yes: bool,
    personal_safety_mode: bool,
    force_risk_acknowledged: bool,
) {
    if personal_safety_mode && !force_risk_acknowledged {
        eprintln!(
            "\n  {} {}\n  Removal is strictly blocked under Personal Safety Mode.\n  Removing surveillance alerts operators, risking retaliatory harm.\n  To override if you have an established safety plan, pass: --force-risk-acknowledged\n",
            "🛡️".yellow(),
            "ACTION BLOCKED BY PERSONAL SAFETY POLICY".bold().yellow()
        );
        return;
    }

    let rm = RemovalManager::new(personal_safety_mode && !force_risk_acknowledged);
    let rules = load_all_rules(None);
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

        if !execute {
            println!("\n  {} {}", "🔍".cyan(), "[DRY RUN] Simulating removal for all SafeAuto findings:".bold());
            for item in &safe_items {
                println!("  Target: {}", item.name);
                if let Ok(planned) = rm.dry_run(item) {
                    for act in planned {
                        println!("    • {}", act);
                    }
                }
            }
            println!("\n  To execute permanent removal, rerun with: {}", "--execute".green());
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
            if !execute {
                println!("\n  {} {}", "🔍".cyan(), format!("[DRY RUN] Simulating removal for '{}':", target.name).bold());
                match rm.dry_run(target) {
                    Ok(planned) => {
                        for act in planned {
                            println!("    • {}", act);
                        }
                        println!("\n  To execute permanent removal, rerun with: {}", "--execute".green());
                    }
                    Err(e) => eprintln!("  ✖ Dry-run failed: {}", e),
                }
                return;
            }

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
    let id_lower = id.trim().to_lowercase();

    // Check if explaining C2 network beaconing
    if id_lower == "stalkerware_c2_network_beacon" || id_lower.starts_with("c2-") || id_lower == "c2" {
        println!("\n  {} {}", "🛡️".cyan(), "THREAT PROFILE: Stalkerware Command-and-Control (C2) Infrastructure".bold());
        println!("  Rule ID: stalkerware_c2_network_beacon | Category: Network Activity | Severity: Critical");
        println!("  Confidence: 1.0 (High) | Policy: SafeAuto (Domain blocking / socket termination)");
        println!("\n  Threat Actor Tactics & MITRE ATT&CK Mapping:");
        println!("    • MITRE Tactic: TA0011 (Command and Control)");
        println!("    • MITRE Technique: T1071 (Application Layer Protocol: Web/DNS Beaconing)");
        println!("    • MITRE Technique: T1041 (Exfiltration Over C2 Channel)");
        println!("    • Reference: https://attack.mitre.org/tactics/TA0011/");
        println!("\n  Real-World Incident Context:");
        println!("    Stalkerware applications exfiltrate keystrokes, GPS coordinates, ambient microphone audio,");
        println!("    and screen captures to remote C2 endpoints controlled by commercial stalkerware vendors.");
        println!("    Sentinel cross-references active connections and DNS cache entries against 280+ curated C2 domains");
        println!("    compiled from Coalition Against Stalkerware, AssoEchap, and Citizen Lab feeds.");
        println!("\n  Incident Triage & Response Protocol:");
        println!("    1. DO NOT immediately terminate or wipe the host if physical safety is at risk.");
        println!("    2. Export forensic report (sentinel scan --stdout-only or save report to external USB).");
        println!("    3. Network Containment: Block the destination domain at router or hosts file ('0.0.0.0 <domain>').");
        println!("    4. Consult trusted support organizations safely:");
        println!("       - Coalition Against Stalkerware: https://stopstalkerware.org");
        println!("       - Global Domestic Violence Helplines: https://lila.help");
        println!();
        return;
    }

    let rules = load_all_rules(None);
    if let Some(rule) = rules.iter().find(|r| r.id.to_lowercase() == id_lower || r.name.to_lowercase().contains(&id_lower)) {
        let (tactic_id, tactic_name, tech_id, tech_name, tech_url) = match rule.category {
            sentinel_core::Category::KeyboardCapture => (
                "TA0009",
                "Collection",
                "T1056.001",
                "Keylogging / Input Capture",
                "https://attack.mitre.org/techniques/T1056/001/",
            ),
            sentinel_core::Category::ScreenCapture => (
                "TA0009",
                "Collection",
                "T1113",
                "Screen Capture",
                "https://attack.mitre.org/techniques/T1113/",
            ),
            sentinel_core::Category::RemoteAccess => (
                "TA0011",
                "Command and Control",
                "T1219",
                "Remote Access Software",
                "https://attack.mitre.org/techniques/T1219/",
            ),
            sentinel_core::Category::OrganizationManaged => (
                "TA0007",
                "Discovery",
                "T1082",
                "System Information Discovery",
                "https://attack.mitre.org/techniques/T1082/",
            ),
            sentinel_core::Category::SuspiciousPersistence => (
                "TA0003",
                "Persistence",
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                "https://attack.mitre.org/techniques/T1547/001/",
            ),
            sentinel_core::Category::NetworkActivity => (
                "TA0011",
                "Command and Control",
                "T1071.001",
                "Web Protocols / C2 Beaconing",
                "https://attack.mitre.org/techniques/T1071/001/",
            ),
            sentinel_core::Category::ProcessWatcher => (
                "TA0005",
                "Defense Evasion",
                "T1562.001",
                "Disable or Modify Tools",
                "https://attack.mitre.org/techniques/T1562/001/",
            ),
        };

        println!("\n  {} [{}] {}", "🛡️".cyan(), rule.id.bold(), rule.name.bold());
        println!("  Vendor: {}", rule.vendor.as_deref().unwrap_or("Unknown"));
        println!("  Category: {:?} | Severity: {:?}", rule.category, rule.severity);
        println!("  Removal Policy: {:?} | Legitimate Dual-Use: {}", rule.removal_policy, rule.is_legitimate_use_likely);

        println!("\n  MITRE ATT&CK Alignment:");
        println!("    • Tactic: {} ({})", tactic_name, tactic_id);
        println!("    • Technique: {} ({})", tech_name, tech_id);
        println!("    • Reference: {}", tech_url);

        println!("\n  Threat Description & Mechanism:");
        for line in rule.description.lines() {
            println!("    {}", line);
        }

        if let Some(warning) = &rule.safety_warning {
            println!("\n  {} Safety Warning:", "⚠".yellow());
            println!("    {}", warning);
        }

        println!("\n  Incident Triage & Response Guidance:");
        match rule.removal_policy {
            sentinel_core::RemovalPolicy::DoNotRemove => {
                println!("    • [ORGANIZATION AGENT] Do NOT attempt removal on corporate-owned devices.");
                println!("    • Tampering triggers alerts in enterprise SOC/SIEM and may violate company acceptable use policy.");
                println!("    • If this is a personal unmanaged machine, consult your IT administrator.");
            }
            sentinel_core::RemovalPolicy::SafeAuto => {
                println!("    • [STALKERWARE / ADWARE] Safe for automated quarantine or removal.");
                println!("    • In personal safety / domestic violence contexts, terminating this software notifies");
                println!("      the perpetrator that their access has been revoked. Ensure personal safety first.");
                println!("    • Safe command: sentinel quarantine {} --execute", rule.id);
            }
            sentinel_core::RemovalPolicy::ManualReview => {
                println!("    • [DUAL-USE / COMPLEX TOOL] Software has valid administrative or productivity use.");
                println!("    • Verify whether this software was intentionally installed by the authorized device owner.");
                println!("    • If unauthorized, follow the manual removal instructions below.");
            }
        }

        if let Some(steps) = &rule.removal {
            let guide = match lang {
                Lang::Ru => steps.manual_steps_windows.as_ref().or(steps.manual_steps_linux.as_ref()),
                Lang::En => steps.manual_steps_windows.as_ref().or(steps.manual_steps_linux.as_ref()),
            };
            if let Some(g) = guide {
                println!("\n  Manual Remediation Procedure:");
                for line in g.lines() {
                    println!("    {}", line);
                }
            }
        }

        if !rule.references.is_empty() {
            println!("\n  Threat Intelligence & References:");
            for r in &rule.references {
                println!("    • {}", r);
            }
        }
        println!();
    } else {
        eprintln!("{} Rule or finding identifier '{}' not found in database.", "✖".red(), id);
        println!("Run 'sentinel rules list' to inspect available rule signatures.");
    }
}

fn load_custom_c2_domains() -> Vec<String> {
    let path = get_sentinel_data_dir().join("c2_domains.txt");
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return content
                .lines()
                .map(|line| line.trim().to_lowercase())
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
        }
    }
    Vec::new()
}

// User allowlist helpers
fn get_allowlist_path() -> PathBuf {
    get_sentinel_data_dir().join("allowlist.json")
}

fn load_user_allowlist_entries() -> HashSet<String> {
    let path = get_allowlist_path();
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(entries) = serde_json::from_str::<Vec<String>>(&content) {
                return entries.into_iter().map(|s| s.to_lowercase()).collect();
            }
        }
    }
    HashSet::new()
}

fn save_user_allowlist_entries(entries: &HashSet<String>) -> std::io::Result<()> {
    let path = get_allowlist_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let list: Vec<String> = entries.iter().cloned().collect();
    let content = serde_json::to_string_pretty(&list)?;
    std::fs::write(path, content)
}

// Merges embedded rules with local rules directory and custom rules
fn load_all_rules(custom_dir: Option<&Path>) -> Vec<sentinel_rules::schema::Rule> {
    let mut rules = get_embedded_rules();
    let local_rules_dir = get_sentinel_data_dir().join("rules");
    if local_rules_dir.exists() {
        if let Ok(extra) = sentinel_rules::load_rules_from_dir(&local_rules_dir) {
            rules.extend(extra);
        }
    }
    if let Some(dir) = custom_dir {
        if dir.exists() {
            if let Ok(extra) = sentinel_rules::load_rules_from_dir(dir) {
                rules.extend(extra);
            }
        }
    }
    rules
}

// Offline disk scanner for forensic mode (--scan-path)
fn run_offline_disk_scan(
    target_root: &Path,
    rules: &[sentinel_rules::schema::Rule],
) -> Vec<sentinel_core::Evidence> {
    println!(
        "  {} Running offline forensic inspection on '{}'...",
        "📁".cyan(),
        target_root.display()
    );
    let mut evidence = Vec::new();

    for entry in walkdir::WalkDir::new(target_root)
        .max_depth(8)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        let path_lower = path_str.to_lowercase();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let file_name_lower = file_name.to_lowercase();

        for rule in rules {
            for p in &rule.detection.processes {
                if file_name_lower == p.name.to_lowercase() {
                    evidence.push(
                        sentinel_core::Evidence::new(
                            sentinel_core::EvidenceType::KnownFileArtifact,
                            "OfflineDiskCollector",
                            format!("Identified signature binary '{}' in offline directory", file_name),
                            format!("Path: {}\nMatched Rule: {}", path_str, rule.id),
                        )
                        .with_data(sentinel_core::EvidenceData::File {
                            path: path_str.clone(),
                            sha256: None,
                            is_signed: None,
                        }),
                    );
                }
            }

            for p in &rule.detection.paths {
                let p_clean = p.trim_start_matches('*').to_lowercase();
                if path_lower.contains(&p_clean) {
                    evidence.push(
                        sentinel_core::Evidence::new(
                            sentinel_core::EvidenceType::KnownFileArtifact,
                            "OfflineDiskCollector",
                            format!("Identified surveillance directory artifact matching rule '{}'", rule.name),
                            format!("Path: {}\nMatched Rule: {}", path_str, rule.id),
                        )
                        .with_data(sentinel_core::EvidenceData::File {
                            path: path_str.clone(),
                            sha256: None,
                            is_signed: None,
                        }),
                    );
                }
            }
        }
    }

    evidence
}

fn execute_purge(yes: bool, reports_dir: &Path, reports_only: bool) {
    if !yes {
        println!();
        if reports_only {
            print!("Are you sure you want to delete all Sentinel audit reports in '{}'? [y/N]: ", reports_dir.display());
        } else {
            print!("Are you sure you want to completely uninstall Sentinel, purge ~/.sentinel, and delete all reports? [y/N]: ");
        }
        use std::io::{self, Write};
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() || !matches!(input.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да") {
            println!("Operation cancelled.");
            return;
        }
    }

    println!();
    println!("  {} {}", "🗑️".red(), "PURGING SENTINEL ARTIFACTS".bold());

    // 1. Delete audit reports in reports_dir and user home dir
    let mut deleted_reports = 0;
    let mut dirs_to_check = vec![reports_dir.to_path_buf()];
    if let Some(home) = dirs::home_dir() {
        if home != reports_dir {
            dirs_to_check.push(home);
        }
    }

    for dir in dirs_to_check {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                        if fname.starts_with("sentinel-report-") && (fname.ends_with(".html") || fname.ends_with(".json") || fname.ends_with(".ndjson")) {
                            if std::fs::remove_file(&path).is_ok() {
                                deleted_reports += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    println!("  • Deleted {} audit report file(s).", deleted_reports);

    if reports_only {
        println!();
        println!("{} Audit reports cleaned successfully.", "✔".green());
        return;
    }

    // 2. Remove ~/.sentinel
    let data_dir = get_sentinel_data_dir();
    if data_dir.exists() {
        match std::fs::remove_dir_all(&data_dir) {
            Ok(_) => println!("  • Removed data directory (~/.sentinel)."),
            Err(e) => eprintln!("  • Failed to remove ~/.sentinel: {}", e),
        }
    }

    // 3. Platform-specific uninstall
    #[cfg(windows)]
    {
        // Clean user PATH
        let install_dir = dirs::data_local_dir()
            .map(|p| p.join("Programs").join("Sentinel"));
        if let Some(ref dir) = install_dir {
            let dir_str = dir.to_string_lossy();
            let script = format!(
                "$p = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($p -like '*{}*') {{ $n = ($p -split ';' | Where-Object {{ $_ -ne '{}' -and $_ -ne '' }}) -join ';'; [Environment]::SetEnvironmentVariable('Path', $n, 'User') }}",
                dir_str, dir_str
            );
            let _ = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &script])
                .output();
            println!("  • Cleaned Sentinel from User PATH.");
        }

        // Schedule self-delete if running from installation folder
        if let Ok(curr_exe) = std::env::current_exe() {
            let parent = curr_exe.parent().unwrap_or(Path::new("."));
            let is_installed_loc = install_dir.as_ref().map_or(false, |d| parent == d.as_path());
            if is_installed_loc {
                let cmd = format!(
                    "timeout /t 1 /nobreak >nul & del /f /q \"{}\" & rmdir /s /q \"{}\"",
                    curr_exe.display(),
                    parent.display()
                );
                let _ = std::process::Command::new("cmd")
                    .args(["/c", &cmd])
                    .spawn();
                println!("  • Scheduled removal of program directory ({}).", parent.display());
            } else {
                println!("  • Standalone binary at '{}'. You may remove it manually.", curr_exe.display());
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Ok(curr_exe) = std::env::current_exe() {
            if std::fs::remove_file(&curr_exe).is_ok() {
                println!("  • Removed Sentinel binary ({}).", curr_exe.display());
            } else {
                println!("  • Note: Remove '{}' manually (may require sudo).", curr_exe.display());
            }
        }
    }

    println!();
    println!("{} Sentinel has been successfully purged.", "✔".green());
}

