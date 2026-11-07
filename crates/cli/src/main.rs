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

mod crypto;
mod mobile;
mod schedule;
mod snapshot;

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

        /// Output format: terminal | json | ndjson | ecs | sarif | csv | stix | html
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

        /// Encrypt the generated report using a password
        #[arg(long)]
        encrypt_report: bool,

        /// Password for report encryption (optional, prompts if omitted)
        #[arg(long)]
        password: Option<String>,
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

    /// Manage system baselines and compute differential change audits
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCommands,
    },

    /// Manage automated recurring surveillance audits (Windows Task Scheduler / systemd)
    Schedule {
        #[command(subcommand)]
        action: ScheduleCommands,
    },

    /// Audit connected Android smartphones via USB ADB bridge
    Mobile {
        #[command(subcommand)]
        action: MobileCommands,
    },

    /// Decrypt a password-protected Sentinel audit report
    Decrypt {
        /// Path to encrypted report (.enc file)
        path: PathBuf,

        /// Destination path for decrypted report
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Decryption password (prompts if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SnapshotCommands {
    /// Save current system state as a baseline snapshot
    Save {
        /// Path to output baseline JSON file
        #[arg(default_value = "baseline.json")]
        path: PathBuf,
    },
    /// Compare current live system state against a previous baseline
    Diff {
        /// Path to previously saved baseline JSON snapshot
        baseline: PathBuf,

        /// Select interface language (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,
    },
}

#[derive(Subcommand, Debug)]
enum ScheduleCommands {
    /// Install an automated background surveillance audit task
    Install {
        /// Run audit daily
        #[arg(long, default_value_t = true)]
        daily: bool,

        /// Run audit hourly
        #[arg(long)]
        hourly: bool,

        /// Run audit upon user logon
        #[arg(long)]
        on_logon: bool,

        /// Time for daily audit (HH:MM format, 24-hour clock)
        #[arg(long, default_value = "10:00")]
        time: String,

        /// Language for audit (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,
    },

    /// Check status of scheduled background audit
    Status {
        /// Language (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,
    },

    /// Remove and deregister scheduled background audit
    Remove {
        /// Language (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,
    },
}

#[derive(Subcommand, Debug)]
enum MobileCommands {
    /// Scan connected Android device or local iOS backup for stalkerware and spyware
    Scan {
        /// Select interface language (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,

        /// Path to local iOS backup directory (optional, auto-detected if omitted)
        #[arg(long)]
        ios: Option<PathBuf>,

        /// Path to MVT (Mobile Verification Toolkit) results directory to correlate
        #[arg(long)]
        mvt: Option<PathBuf>,
    },

    /// Import and correlate Mobile Verification Toolkit (MVT) forensic results
    #[command(alias = "import")]
    ImportMvt {
        /// Path to MVT results directory or JSON file (e.g. mvt-output/ or records.json)
        path: PathBuf,

        /// Select interface language (en | ru)
        #[arg(short, long, default_value = "en")]
        lang: String,
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
    /// Export C2 domains in Suricata (TinyCheck/Snort), hosts, or plain domain format
    #[command(alias = "export")]
    ExportC2 {
        /// Export format: suricata (TinyCheck/Snort), hosts (Pi-hole/AdGuard), or domains (plain list)
        #[arg(long, default_value = "suricata")]
        format: String,

        /// Output file path (prints to stdout if omitted)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Starting SID for Suricata rules (defaults to 9000000)
        #[arg(long, default_value_t = 9000000)]
        sid_start: u32,
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
            encrypt_report,
            password,
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
                encrypt_report,
                password,
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
            RulesCommands::ExportC2 { format, out, sid_start } => {
                let custom_c2 = load_custom_c2_domains();
                let content = match format.to_lowercase().as_str() {
                    "suricata" | "snort" | "tinycheck" => {
                        sentinel_rules::export_suricata_rules(&custom_c2, sid_start)
                    }
                    "hosts" => sentinel_rules::export_hosts_format(&custom_c2),
                    "domains" | "list" => sentinel_rules::export_domains_list(&custom_c2),
                    other => {
                        eprintln!("{} Unknown export format '{}'. Supported: suricata, hosts, domains", "✖".red(), other);
                        return;
                    }
                };

                if let Some(dest) = out {
                    match std::fs::write(&dest, &content) {
                        Ok(_) => println!("{} Exported {} C2 indicators to '{}' (format: {}).", "✔".green(), sentinel_rules::get_all_c2_domains(&custom_c2).len(), dest.display(), format),
                        Err(e) => eprintln!("{} Failed to write to '{}': {}", "✖".red(), dest.display(), e),
                    }
                } else {
                    print!("{}", content);
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
        Commands::Snapshot { action } => match action {
            SnapshotCommands::Save { path } => {
                println!("  {} Generating baseline system snapshot...", "📸".cyan());
                let platform = PlatformInfo::current();
                let collectors = get_all_collectors();
                let ctx = CollectorContext {
                    platform: platform.clone(),
                    privilege_level: platform.privilege_level,
                    timeout: std::time::Duration::from_secs(15),
                };
                let (evidence, _) = run_collectors(&collectors, &ctx);
                let snap = snapshot::create_snapshot(&evidence);
                if let Err(e) = snapshot::save_snapshot(&snap, &path) {
                    eprintln!("Failed to save baseline snapshot: {}", e);
                } else {
                    println!("  {} Baseline snapshot saved: {}", "✔".green().bold(), path.display().to_string().cyan());
                    println!("     Processes: {}, Services: {}, Autostart: {}, Ports: {}, Extensions: {}",
                        snap.processes.len(), snap.services.len(), snap.autostart.len(), snap.listening_ports.len(), snap.browser_extensions.len());
                }
            }
            SnapshotCommands::Diff { baseline, lang } => {
                let l = Lang::from_code(&lang);
                println!("  {} Loading baseline snapshot: {}...", "🔍".cyan(), baseline.display());
                let base_snap = match snapshot::load_snapshot(&baseline) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Failed to read baseline snapshot: {}", e);
                        return;
                    }
                };
                println!("  {} Collecting current system state for differential comparison...", "⏱️".cyan());
                let platform = PlatformInfo::current();
                let collectors = get_all_collectors();
                let ctx = CollectorContext {
                    platform: platform.clone(),
                    privilege_level: platform.privilege_level,
                    timeout: std::time::Duration::from_secs(15),
                };
                let (evidence, _) = run_collectors(&collectors, &ctx);
                let curr_snap = snapshot::create_snapshot(&evidence);
                let diff = snapshot::compute_diff(&base_snap, &curr_snap);
                snapshot::print_diff_summary(&diff, l);
            }
        },
        Commands::Schedule { action } => match action {
            ScheduleCommands::Install { daily, hourly, on_logon, time, lang } => {
                let l = Lang::from_code(&lang);
                if let Err(e) = schedule::install_schedule(daily, hourly, on_logon, &time, l) {
                    eprintln!("{} Failed to configure scheduled audit: {}", "❌".red().bold(), e);
                }
            }
            ScheduleCommands::Status { lang } => {
                let l = Lang::from_code(&lang);
                if let Err(e) = schedule::check_schedule_status(l) {
                    eprintln!("{} Failed to check schedule status: {}", "❌".red().bold(), e);
                }
            }
            ScheduleCommands::Remove { lang } => {
                let l = Lang::from_code(&lang);
                if let Err(e) = schedule::remove_schedule(l) {
                    eprintln!("{} Failed to remove scheduled audit: {}", "❌".red().bold(), e);
                }
            }
        },
        Commands::Mobile { action } => match action {
            MobileCommands::Scan { lang, ios, mvt } => {
                let l = Lang::from_code(&lang);
                if let Some(mvt_path) = mvt {
                    if let Err(e) = mobile::import_mvt_results(l, &mvt_path) {
                        eprintln!("{} MVT audit error: {}", "❌".red().bold(), e);
                    }
                }
                if let Err(e) = mobile::scan_connected_mobile_device(l, ios.as_deref()) {
                    eprintln!("{} Mobile scan error: {}", "❌".red().bold(), e);
                }
            }
            MobileCommands::ImportMvt { path, lang } => {
                let l = Lang::from_code(&lang);
                if let Err(e) = mobile::import_mvt_results(l, &path) {
                    eprintln!("{} MVT import error: {}", "❌".red().bold(), e);
                }
            }
        },
        Commands::Decrypt { path, out, password } => {
            let password_str = password.unwrap_or_else(|| {
                println!("Enter decryption password: ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap_or_default();
                input.trim().to_string()
            });
            let out_path = out.unwrap_or_else(|| {
                let s = path.to_string_lossy().to_string();
                if s.ends_with(".enc") {
                    PathBuf::from(&s[..s.len() - 4])
                } else {
                    PathBuf::from(format!("{}.decrypted", s))
                }
            });
            match crypto::decrypt_report_file(&path, &out_path, &password_str) {
                Ok(_) => println!("{} Decrypted report successfully saved to: {}", "✔".green().bold(), out_path.display().to_string().cyan()),
                Err(e) => eprintln!("{} Decryption failed: {}", "❌".red().bold(), e),
            }
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
    encrypt_report: bool,
    password: Option<String>,
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

    if format_opt == "sarif" {
        let sarif_val = sentinel_report::generate_sarif_report(&result);
        if let Ok(s) = serde_json::to_string_pretty(&sarif_val) {
            println!("{}", s);
        }
        return;
    }

    if format_opt == "csv" {
        print!("{}", sentinel_report::generate_csv_report(&result));
        return;
    }

    if format_opt == "stix" {
        let stix_val = sentinel_report::generate_stix_report(&result);
        if let Ok(s) = serde_json::to_string_pretty(&stix_val) {
            println!("{}", s);
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

    if format_opt == "sarif" {
        let sarif_path = out_dir.join(format!("sentinel-report-{}.sarif", date_tag));
        if let Err(e) = sentinel_report::export_sarif_report(&result, &sarif_path) {
            eprintln!("Failed to write SARIF report: {}", e);
        } else {
            println!("  SARIF export generated: {}", sarif_path.display().to_string().cyan());
        }
    }

    if format_opt == "csv" {
        let csv_path = out_dir.join(format!("sentinel-report-{}.csv", date_tag));
        if let Err(e) = sentinel_report::export_csv_report(&result, &csv_path) {
            eprintln!("Failed to write CSV report: {}", e);
        } else {
            println!("  CSV export generated: {}", csv_path.display().to_string().cyan());
        }
    }

    if format_opt == "stix" {
        let stix_path = out_dir.join(format!("sentinel-report-{}.stix.json", date_tag));
        if let Err(e) = sentinel_report::export_stix_report(&result, &stix_path) {
            eprintln!("Failed to write STIX report: {}", e);
        } else {
            println!("  STIX 2.1 export generated: {}", stix_path.display().to_string().cyan());
        }
    }

    if encrypt_report {
        let password_str = password.unwrap_or_else(|| {
            println!("Enter encryption password for audit report: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            input.trim().to_string()
        });
        if !password_str.is_empty() {
            let enc_html = out_dir.join(format!("sentinel-report-{}.html.enc", date_tag));
            if let Ok(_) = crypto::encrypt_report_file(&html_path, &enc_html, &password_str) {
                let _ = std::fs::remove_file(&html_path);
                println!("  🔒 Encrypted report created: {}", enc_html.display().to_string().green());
                println!("     (Plaintext report removed. Use 'sentinel decrypt {}' to view)", enc_html.display());
            }
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

    // Check if explaining Hidden Process Discrepancies (DKOM / Rootkits)
    if id_lower.contains("discrepancy") || id_lower == "rootkit" || id_lower == "dkom" {
        println!("\n  {} {}", "🛡️".cyan(), "THREAT PROFILE: Hidden Process Discrepancy (DKOM / Rootkit Anomaly)".bold());
        println!("  Rule ID: hidden_process_discrepancy | Category: Process Watcher / Defense Evasion | Severity: Critical");
        println!("  Confidence: 0.95 (High) | Policy: ManualReview (Memory inspection / live triage)");
        println!("\n  Threat Actor Tactics & MITRE ATT&CK Mapping:");
        println!("    • MITRE Tactic: TA0005 (Defense Evasion)");
        println!("    • MITRE Technique: T1014 (Rootkit: Direct Kernel Object Manipulation / DKOM)");
        println!("    • MITRE Technique: T1057 (Process Discovery)");
        println!("    • Reference: https://attack.mitre.org/techniques/T1014/");
        println!("\n  Real-World Incident Context:");
        println!("    Rootkits and advanced spyware unhook or unlink their processes from the EPROCESS active list (DKOM)");
        println!("    to hide from Task Manager, Process Explorer, and standard toolhelp enumeration.");
        println!("    Sentinel detected this anomaly by cross-checking low-level system process tables against alternate OS APIs.");
        println!("\n  Incident Triage & Response Protocol:");
        println!("    1. Do not reboot immediately if forensic memory capture is required.");
        println!("    2. Capture full physical memory dump (using WinPmem or LiME) for offline Volatility analysis.");
        println!("    3. Reboot into safe mode or bootable rescue media to scan the disk offline.");
        println!();
        return;
    }

    // Check if explaining Hardware USB Keyloggers & Rogue HID Devices
    if id_lower.contains("hardware") || id_lower.contains("keylogger") || id_lower.contains("badusb") {
        println!("\n  {} {}", "🛡️".cyan(), "THREAT PROFILE: Hardware Keylogger or Rogue USB Keystroke Injector".bold());
        println!("  Rule ID: hardware_usb_keylogger | Category: Keyboard Capture | Severity: Critical");
        println!("  Confidence: 0.90 (High) | Policy: ManualReview (Physical inspection)");
        println!("\n  Threat Actor Tactics & MITRE ATT&CK Mapping:");
        println!("    • MITRE Tactic: TA0009 (Collection)");
        println!("    • MITRE Technique: T1056.001 (Input Capture: Keylogging)");
        println!("    • MITRE Technique: T1200 (Hardware Additions: USB In-Line Interceptor / BadUSB)");
        println!("    • Reference: https://attack.mitre.org/techniques/T1200/");
        println!("\n  Real-World Incident Context:");
        println!("    Hardware keyloggers (e.g. KeyGrabber, Hak5 Key Croc, Teensy/BadUSB) are physical USB devices");
        println!("    connected in-line between the keyboard and the computer port, recording every keystroke or injecting payloads.");
        println!("\n  Incident Triage & Response Protocol:");
        println!("    1. Physically inspect the back of the computer and follow the keyboard cable directly to the USB port.");
        println!("    2. Look for unexpected dongles, barrel connectors, or USB hubs inserted between the cable and the chassis.");
        println!("    3. Unplug any unknown USB adapters and disconnect the machine from the network immediately.");
        println!();
        return;
    }

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

        println!("\n  Confidential Support & Emergency Hotlines:");
        match lang {
            Lang::Ru => {
                println!("    • Международный каталог кризисных центров: https://lila.help");
                println!("    • Коалиция против сталкерского ПО: https://stopstalkerware.org");
                println!("    • Всероссийский телефон доверия для женщин: 8-800-7000-600 (Центр «Анна»)");
                println!("    • Центр помощи пережившим насилие «Насилию.нет»: +7 (495) 916-30-00");
                println!("    • Кризисный центр помощи женщинам «Сёстры»: https://sestry-online.ru");
            }
            Lang::En => {
                println!("    • Global Directory of Local Support: https://lila.help");
                println!("    • Coalition Against Stalkerware: https://stopstalkerware.org");
                println!("    • US National Domestic Violence Hotline: 1-800-799-SAFE (88788 text 'START')");
                println!("    • UK National Domestic Abuse Helpline: 0808 2000 247 (Refuge)");
                println!("    • European Emergency Number: 112 | EU Domestic Violence Hotline: 116 016");
                println!("    • Cyber Civil Rights Initiative: https://cybercivilrights.org");
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

