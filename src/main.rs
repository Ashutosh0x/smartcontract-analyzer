use clap::{Parser, Subcommand};
use smartcontract_analyzer::{Sentinel, SentinelConfig, PipelineStage};
use smartcontract_analyzer::reporting::ReportFormat;
use smartcontract_analyzer::detectors::Severity;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sentinel")]
#[command(version, about = "Sentinel: Professional-grade smart contract security analyzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to config file
    #[arg(global = true, long, default_value = "sentinel.toml")]
    config: String,

    /// Enable verbose output
    #[arg(global = true, short, long)]
    verbose: bool,

    /// Suppress non-essential output
    #[arg(global = true, short, long)]
    quiet: bool,

    /// Disable colored output
    #[arg(global = true, long)]
    no_color: bool,

    /// Number of analysis threads (0 = auto)
    #[arg(global = true, long, default_value = "0")]
    threads: usize,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a project or directory for vulnerabilities
    Scan {
        /// Path to scan
        #[arg(default_value = ".")]
        path: String,

        /// Enable deep analysis (semantic + data-flow + taint)
        #[arg(long)]
        deep: bool,

        /// Enable maximum analysis (+ fuzzing hints, symbolic, exploit sim)
        #[arg(long, name = "max")]
        max_mode: bool,

        /// Minimum severity to report
        #[arg(long, default_value = "low")]
        severity: String,

        /// Output SARIF format
        #[arg(long)]
        sarif: bool,

        /// Output JSON format
        #[arg(long)]
        json: bool,

        /// Output Markdown format
        #[arg(long)]
        markdown: bool,

        /// Output HTML format
        #[arg(long)]
        html: bool,

        /// Analyze bytecode instead of source
        #[arg(long)]
        bytecode: bool,

        /// Only scan changed files
        #[arg(long)]
        changed: bool,

        /// Use baseline for differential scanning
        #[arg(long)]
        baseline: Option<String>,
    },

    /// Explain a specific detector
    Explain {
        /// Detector ID (e.g., REENTRANCY-001)
        detector_id: String,
    },

    /// Compare findings between two revisions
    Diff {
        /// Start revision
        from: String,
        /// End revision
        to: String,
    },

    /// Manage analysis baselines
    Baseline {
        #[command(subcommand)]
        command: BaselineCommands,
    },

    /// List all available detectors
    ListDetectors,

    /// Update security rules and knowledge base
    UpdateRules,
}

#[derive(Subcommand, Debug)]
enum BaselineCommands {
    /// Create a new baseline from current scan
    Create,
    /// Check against existing baseline
    Check,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("sentinel=debug")
            .init();
    } else if !cli.quiet {
        tracing_subscriber::fmt()
            .with_env_filter("sentinel=info")
            .init();
    }

    match &cli.command {
        Commands::Scan {
            path,
            deep,
            max_mode,
            severity,
            sarif,
            json,
            markdown,
            bytecode: _,
            changed: _,
            baseline: _,
            html: _,
        } => {
            let stage = if *max_mode {
                PipelineStage::Max
            } else if *deep {
                PipelineStage::Deep
            } else {
                PipelineStage::Fast
            };

            let config = SentinelConfig {
                severity_threshold: parse_severity(severity),
                ..SentinelConfig::default()
            };

            let sentinel = Sentinel::new(config, stage);
            let target = PathBuf::from(path);

            eprintln!("🔍 Sentinel — Smart Contract Security Analyzer");
            eprintln!("   Scanning: {}", path);
            eprintln!("   Mode: {:?}", stage);
            eprintln!();

            let findings = sentinel.analyze(&target)?;

            // Determine output format
            let format = if *sarif {
                ReportFormat::Sarif
            } else if *json {
                ReportFormat::Json
            } else if *markdown {
                ReportFormat::Markdown
            } else {
                ReportFormat::Terminal
            };

            let output = sentinel.report(&findings, path, format)?;
            println!("{output}");

            // Exit with non-zero if critical/high findings
            let has_critical = findings.iter().any(|f| {
                matches!(f.severity, Severity::Critical | Severity::High)
            });
            if has_critical {
                std::process::exit(1);
            }
        }

        Commands::Explain { detector_id } => {
            let mut registry = smartcontract_analyzer::detectors::DetectorRegistry::new();
            registry.register_defaults();

            if let Some(detector) = registry.get_detector(detector_id) {
                let meta = detector.metadata();
                println!("Detector: {}", meta.id);
                println!("Name: {}", meta.name);
                println!("Category: {:?}", meta.category);
                println!("Severity: {:?}", meta.severity);
                println!("Confidence: {:?}", meta.confidence);
                println!("Description: {}", meta.description);
                if !meta.cwe.is_empty() {
                    println!("CWE: {}", meta.cwe.join(", "));
                }
                if !meta.swc.is_empty() {
                    println!("SWC: {}", meta.swc.join(", "));
                }
            } else {
                eprintln!("Unknown detector: {detector_id}");
                eprintln!("Use 'sentinel list-detectors' to see available detectors.");
                std::process::exit(1);
            }
        }

        Commands::ListDetectors => {
            let mut registry = smartcontract_analyzer::detectors::DetectorRegistry::new();
            registry.register_defaults();

            println!("{:<20} {:<40} {:<10} {:<10}", "ID", "NAME", "SEVERITY", "CATEGORY");
            println!("{}", "-".repeat(80));
            for meta in registry.list_detectors() {
                println!(
                    "{:<20} {:<40} {:<10} {:?}",
                    meta.id, meta.name, format!("{:?}", meta.severity), meta.category
                );
            }
        }

        Commands::Diff { from, to } => {
            eprintln!("Comparing {from} → {to} (not yet implemented)");
        }

        Commands::Baseline { command } => match command {
            BaselineCommands::Create => {
                eprintln!("Creating baseline... (not yet implemented)");
            }
            BaselineCommands::Check => {
                eprintln!("Checking against baseline... (not yet implemented)");
            }
        },

        Commands::UpdateRules => {
            eprintln!("Updating security rules... (not yet implemented)");
        }
    }

    Ok(())
}
