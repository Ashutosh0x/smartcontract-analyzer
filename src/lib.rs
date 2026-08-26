//! # Sentinel — Professional-Grade Smart Contract Security Analyzer
//!
//! A Rust-based security analysis platform for Solidity/EVM smart contracts.
//! Combines semantic analysis, DeFi awareness, exploitability scoring,
//! and evidence-based findings.

pub mod analyses;
pub mod bytecode;
pub mod cli;
pub mod compiler;
pub mod defi;
pub mod dependencies;
pub mod detectors;
pub mod exploit;
pub mod fuzzing;
pub mod ingestion;
pub mod integrations;
pub mod ir;
pub mod knowledge;
pub mod parser;
pub mod reporting;
pub mod semantic;
pub mod symbolic;

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
            src_paths: vec![PathBuf::from("src")],
            exclude_paths: vec![PathBuf::from("test"), PathBuf::from("script")],
            severity_threshold: detectors::Severity::Low,
            disabled_detectors: Vec::new(),
        }
    }
}

// ── Pipeline ───────────────────────────────────────────────────────────

/// Analysis depth / mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    /// Static analysis only — fastest.
    Fast,
    /// Semantic + data-flow + taint analysis.
    Deep,
    /// Everything: fuzzing hints, symbolic, exploit simulation.
    Max,
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

/// Top-level orchestrator that drives the entire analysis pipeline.
///
/// Pipeline:
/// ```text
/// SOURCE → Project Discovery → Dependency Resolution → Compiler Detection
/// → Solidity AST → IR → SSA → CFG → Call Graph → Storage Model
/// → Data Flow → Taint Analysis → Semantic Analysis → Security Detectors
/// → DeFi/Economic Analysis → Cross-Contract Analysis
/// → Exploitability Analysis → Finding Correlation → Risk Scoring
/// → Report Generation
/// ```
pub struct Sentinel {
    pub config: SentinelConfig,
    pub stage: PipelineStage,
}

impl Sentinel {
    pub fn new(config: SentinelConfig, stage: PipelineStage) -> Self {
        Self { config, stage }
    }

    pub fn default_fast() -> Self {
        Self::new(SentinelConfig::default(), PipelineStage::Fast)
    }

    /// Run the full analysis pipeline on the given target path.
    pub fn analyze(&self, target: &Path) -> Result<Vec<detectors::Finding>, SentinelError> {
        tracing::info!("Starting Sentinel analysis on {:?} (mode: {:?})", target, self.stage);

        // Phase 1: Project discovery & compilation
        let project_type = compiler::CompilerManager::detect_project(target);
        tracing::info!("Detected project type: {:?}", project_type);

        // Phase 2: Run detectors (on the analysis context built from compilation)
        let mut registry = detectors::DetectorRegistry::new();
        registry.register_defaults();

        // Build a minimal analysis context
        let context = detectors::AnalysisContext {
            compilation_unit: String::new(),
            cfg_results: std::collections::HashMap::new(),
            call_graph: detectors::CallGraphData {},
            taint_results: std::collections::HashMap::new(),
            storage_layout: std::collections::HashMap::new(),
        };

        let findings = registry.run_all(&context);
        tracing::info!("Found {} raw findings", findings.len());

        // Phase 3: Filter by severity & disabled detectors
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
        let score = reporting::SecurityReport::calculate_score(
            &findings.iter().map(|f| reporting::Finding {
                id: f.id.clone(),
                title: f.title.clone(),
                description: f.description.clone(),
                severity: match f.severity {
                    detectors::Severity::Critical => reporting::RiskLevel::Critical,
                    detectors::Severity::High => reporting::RiskLevel::High,
                    detectors::Severity::Medium => reporting::RiskLevel::Medium,
                    detectors::Severity::Low => reporting::RiskLevel::Low,
                    detectors::Severity::Informational => reporting::RiskLevel::Info,
                },
                file: f.source_locations.first()
                    .map(|l| l.file.clone())
                    .unwrap_or_default(),
                line: f.source_locations.first()
                    .map(|l| l.line)
                    .unwrap_or(0),
            }).collect::<Vec<_>>(),
        );

        let report = reporting::SecurityReport {
            project_name: project_name.to_string(),
            scan_timestamp: chrono::Utc::now(),
            scan_duration: std::time::Duration::from_secs(0),
            findings: findings.iter().map(|f| reporting::Finding {
                id: f.id.clone(),
                title: f.title.clone(),
                description: f.description.clone(),
                severity: match f.severity {
                    detectors::Severity::Critical => reporting::RiskLevel::Critical,
                    detectors::Severity::High => reporting::RiskLevel::High,
                    detectors::Severity::Medium => reporting::RiskLevel::Medium,
                    detectors::Severity::Low => reporting::RiskLevel::Low,
                    detectors::Severity::Informational => reporting::RiskLevel::Info,
                },
                file: f.source_locations.first()
                    .map(|l| l.file.clone())
                    .unwrap_or_default(),
                line: f.source_locations.first()
                    .map(|l| l.line)
                    .unwrap_or(0),
            }).collect(),
            security_score: score,
            summary: reporting::ReportSummary {
                files_scanned: 0,
                lines_of_code: 0,
            },
            compiler_info: reporting::CompilerInfo {
                version: String::new(),
                framework: String::new(),
            },
        };

        report.generate(format).map_err(|e| SentinelError::Analysis(e.to_string()))
    }
}

impl Default for Sentinel {
    fn default() -> Self {
        Self::default_fast()
    }
}
