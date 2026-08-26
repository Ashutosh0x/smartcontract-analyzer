//! # Sentinel — Rust-Native Smart Contract Security Analyzer
//!
//! Static analysis for Solidity/EVM smart contracts.
//! Uses `solang-parser` for Solidity parsing and `solc --standard-json`
//! for fully-resolved AST with type info.
//!
//! ## Architecture
//! ```text
//! SOURCE → Project Discovery → solc Compilation → AST Parsing
//! → WorkspaceContext → Detectors → Findings → Report
//! ```

pub mod ast;
pub mod compiler;
pub mod context;
pub mod detectors;
pub mod ingestion;
pub mod printers;
pub mod reporting;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── Configuration ──────────────────────────────────────────────────────

/// Top-level configuration for a Sentinel analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub max_depth: u32,
    pub timeout_seconds: u32,
    pub src_paths: Vec<PathBuf>,
    pub exclude_paths: Vec<PathBuf>,
    pub severity_threshold: detectors::Severity,
    pub disabled_detectors: Vec<String>,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            timeout_seconds: 300,
            src_paths: vec![PathBuf::from("src"), PathBuf::from("contracts")],
            exclude_paths: vec![PathBuf::from("test"), PathBuf::from("script"), PathBuf::from("node_modules")],
            severity_threshold: detectors::Severity::Low,
            disabled_detectors: Vec::new(),
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Compilation error: {0}")]
    Compilation(String),
    #[error("Analysis error: {0}")]
    Analysis(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// ── Orchestrator ───────────────────────────────────────────────────────

/// Top-level orchestrator that drives the analysis pipeline.
///
/// Pipeline:
/// 1. Discover project type (Foundry, Hardhat, bare Solidity)
/// 2. Find all .sol source files
/// 3. Parse each file with solang-parser to get AST
/// 4. Build WorkspaceContext (indexed AST nodes)
/// 5. Run all enabled detectors against the context
/// 6. Filter, deduplicate, and score findings
/// 7. Generate report
pub struct Sentinel {
    pub config: SentinelConfig,
}

impl Sentinel {
    pub fn new(config: SentinelConfig) -> Self {
        Self { config }
    }

    /// Run the analysis pipeline on the given target path.
    pub fn analyze(&self, target: &Path) -> Result<Vec<detectors::Finding>, SentinelError> {
        tracing::info!("Starting Sentinel analysis on {:?}", target);

        // Phase 1: Discover project and find Solidity files
        let project = ingestion::ProjectDiscoverer::discover(target)
            .map_err(|e| SentinelError::Analysis(format!("{:?}", e)))?;
        tracing::info!("Detected project: {:?}, {} source files", project.project_type, project.source_files.len());

        // Phase 2: Parse all Solidity files into ASTs
        let mut parsed_sources = Vec::new();
        for source_path in &project.source_files {
            match std::fs::read_to_string(source_path) {
                Ok(source) => {
                    match ast::parse_solidity(&source, source_path) {
                        Ok(parsed) => parsed_sources.push(parsed),
                        Err(e) => {
                            tracing::warn!("Parse error in {:?}: {}", source_path, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Could not read {:?}: {}", source_path, e);
                }
            }
        }
        tracing::info!("Successfully parsed {} / {} files", parsed_sources.len(), project.source_files.len());

        // Phase 3: Build workspace context (indexed AST data)
        let ctx = context::WorkspaceContext::from_parsed_sources(&parsed_sources);
        tracing::info!(
            "WorkspaceContext: {} contracts, {} functions, {} state variables",
            ctx.contracts.len(),
            ctx.functions.len(),
            ctx.state_variables.len(),
        );

        // Phase 4: Run detectors
        let mut registry = detectors::DetectorRegistry::new();
        registry.register_defaults();

        let findings = registry.run_all(&ctx);
        tracing::info!("Found {} raw findings", findings.len());

        // Phase 5: Filter by severity & disabled detectors, apply suppressions
        let findings: Vec<_> = findings
            .into_iter()
            .filter(|f| f.severity >= self.config.severity_threshold)
            .filter(|f| !self.config.disabled_detectors.contains(&f.detector_id))
            .collect();

        Ok(findings)
    }

    /// Generate a security report from findings.
    pub fn report(
        &self,
        findings: &[detectors::Finding],
        project_name: &str,
        format: reporting::ReportFormat,
    ) -> Result<String, SentinelError> {
        let report = reporting::SecurityReport::new(
            project_name.to_string(),
            findings.to_vec(),
        );
        Ok(report.generate(format))
    }
}

impl Default for Sentinel {
    fn default() -> Self {
        Self::new(SentinelConfig::default())
    }
}
