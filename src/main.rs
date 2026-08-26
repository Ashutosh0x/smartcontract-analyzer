use clap::{Parser, Subcommand};
use smartcontract_analyzer::{Sentinel, SentinelConfig};
use smartcontract_analyzer::reporting::ReportFormat;
use smartcontract_analyzer::detectors::{DetectorRegistry, Severity};
use smartcontract_analyzer::printers;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "sentinel")]
#[command(version, about = "Sentinel: Rust-native smart contract security analyzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a project or directory for vulnerabilities
    Scan {
        /// Path to scan
        #[arg(default_value = ".")]
        path: String,

        /// Output JSON format
        #[arg(long)]
        json: bool,

        /// Output SARIF format
        #[arg(long)]
        sarif: bool,

        /// Output Markdown format
        #[arg(long)]
        markdown: bool,

        /// Minimum severity to report (critical, high, medium, low, informational)
        #[arg(long, default_value = "low")]
        severity: String,

        /// Output file
        #[arg(long, short)]
        output: Option<String>,
    },

    /// List all available detectors
    ListDetectors,

    /// Print project structures for auditing
    Print {
        /// Type: inheritance, functions, state-vars, external-calls, permissions
        #[arg(value_name = "TYPE")]
        print_type: String,

        /// Path to project
        #[arg(default_value = ".")]
        path: String,
    },
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "informational" | "info" => Severity::Informational,
        _ => Severity::Low,
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path, json, sarif, markdown, severity, output } => {
            let config = SentinelConfig {
                severity_threshold: parse_severity(severity),
                ..SentinelConfig::default()
            };

            let sentinel = Sentinel::new(config);
            let target = Path::new(path);

            let findings = sentinel.analyze(target)?;

            let format = if *json {
                ReportFormat::Json
            } else if *sarif {
                ReportFormat::Sarif
            } else if *markdown {
                ReportFormat::Markdown
            } else {
                ReportFormat::Terminal
            };

            let report_str = sentinel.report(&findings, path, format)?;

            if let Some(out_path) = output {
                std::fs::write(out_path, &report_str)?;
                eprintln!("Report written to {}", out_path);
            } else {
                println!("{}", report_str);
            }
        }
        Commands::ListDetectors => {
            let mut registry = DetectorRegistry::new();
            registry.register_defaults();

            println!("{:<20} {:<45} {:<12} {:<10}", "ID", "TITLE", "SEVERITY", "CONFIDENCE");
            println!("{}", "-".repeat(87));
            for info in registry.list() {
                println!("{:<20} {:<45} {:<12?} {:<10?}", info.0, info.1, info.2, info.3);
            }
        }
        Commands::Print { print_type, path } => {
            let target = Path::new(path);

            // Parse the project to build context
            let project = smartcontract_analyzer::ingestion::ProjectDiscoverer::discover(target)?;
            let mut parsed_sources = Vec::new();
            for source_path in &project.source_files {
                if let Ok(source) = std::fs::read_to_string(source_path) {
                    if let Ok(parsed) = smartcontract_analyzer::ast::parse_solidity(&source, source_path) {
                        parsed_sources.push(parsed);
                    }
                }
            }
            let ctx = smartcontract_analyzer::context::WorkspaceContext::from_parsed_sources(&parsed_sources);

            let output_str = match print_type.as_str() {
                "inheritance" => printers::print_inheritance(&ctx),
                "functions" => printers::print_functions(&ctx),
                "state-vars" => printers::print_state_variables(&ctx),
                "external-calls" => printers::print_external_calls(&ctx),
                "permissions" => printers::print_permissions(&ctx),
                _ => {
                    eprintln!("Unknown print type: {}. Use: inheritance, functions, state-vars, external-calls, permissions", print_type);
                    std::process::exit(1);
                }
            };
            println!("{}", output_str);
        }
    }

    Ok(())
}
