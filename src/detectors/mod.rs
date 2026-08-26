use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// We assume crate::ir exists as per user request.
// If it doesn't, this will fail compilation. We provide mock types here in case.
pub mod reentrancy;
pub mod unchecked_call;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

// These types are just to satisfy compilation based on the prompt's provided snippet.
// Normally they'd be in crate::ir::* but we need to ensure it compiles.
pub type FunctionId = String;
pub type CompilationUnit = String;

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Confidence levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Exploitability assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityAssessment {
    pub attacker_controlled: bool,
    pub externally_reachable: bool,
    pub requires_privilege: bool,
    pub reachable_from_public: bool,
    pub state_changing: bool,
    pub funds_at_risk: RiskLevel,
    pub attack_complexity: AttackComplexity,
    pub required_privilege: PrivilegeLevel,
    pub flash_loan_dependency: bool,
    pub oracle_dependency: bool,
    pub upgrade_dependency: bool,
    pub confidence_score: f64, // 0.0-1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel { None, Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackComplexity { Low, Medium, High }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegeLevel { None, Low, High, Admin }

/// Evidence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub description: String,
    pub source_location: SourceLocation,
    pub code_snippet: Option<String>,
    pub data_flow_trace: Vec<DataFlowStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowStep {
    pub step_number: usize,
    pub description: String,
    pub source_location: SourceLocation,
}

/// Attack path (ordered steps)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub steps: Vec<AttackStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub step_number: usize,
    pub actor: String,
    pub action: String,
    pub function: String,
    pub source_location: Option<SourceLocation>,
    pub state_change: Option<String>,
}

/// Security finding - the main output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,               // e.g., "REENTRANCY-001"
    pub detector_id: String,      // which detector found it
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: DetectorCategory,
    pub evidence: Vec<Evidence>,
    pub attack_path: Option<AttackPath>,
    pub exploitability: Option<ExploitabilityAssessment>,
    pub remediation: String,
    pub references: Vec<Reference>,
    pub source_locations: Vec<SourceLocation>,
    pub affected_contracts: Vec<String>,
    pub affected_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub ref_type: ReferenceType,
    pub id: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferenceType { CWE, SWC, EIP, ERC, EthTrust, OWASP, Custom }

/// Detector categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectorCategory {
    Reentrancy,
    AccessControl,
    Arithmetic,
    Oracle,
    Proxy,
    Token,
    Signature,
    DeFi,
    FlashLoan,
    Compiler,
    DoS,
    CrossChain,
    MEV,
    Governance,
    Dependencies,
    Gas,
    CodeQuality,
}

/// Detector metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: DetectorCategory,
    pub severity: Severity,
    pub confidence: Confidence,
    pub cwe: Vec<String>,
    pub swc: Vec<String>,
    pub eip: Vec<String>,
    pub affected_solidity_versions: Option<String>,
    pub affected_compiler_versions: Option<String>,
}

/// The core detector trait - all detectors implement this
pub trait Detector: Send + Sync {
    fn metadata(&self) -> DetectorMetadata;
    fn detect(&self, context: &AnalysisContext) -> Vec<Finding>;
    fn name(&self) -> &str;
}

/// Analysis context provided to detectors
pub struct AnalysisContext {
    pub compilation_unit: CompilationUnit,
    pub cfg_results: HashMap<FunctionId, CfgData>,
    pub call_graph: CallGraphData,
    pub taint_results: HashMap<FunctionId, TaintData>,
    pub storage_layout: HashMap<String, StorageLayoutData>,
}

// Placeholder data types for analysis results
pub struct CfgData { /* TODO */ }
pub struct CallGraphData { /* TODO */ }
pub struct TaintData { /* TODO */ }
pub struct StorageLayoutData { /* TODO */ }

/// Detector registry
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self { detectors: Vec::new() }
    }
    
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }
    
    pub fn register_defaults(&mut self) {
        self.register(Box::new(reentrancy::ReentrancyDetector::new()));
        self.register(Box::new(unchecked_call::UncheckedCallDetector::new()));
    }
    
    pub fn run_all(&self, context: &AnalysisContext) -> Vec<Finding> {
        let mut all_findings = Vec::new();
        for detector in &self.detectors {
            all_findings.extend(detector.detect(context));
        }
        all_findings
    }
    
    pub fn run_category(&self, category: DetectorCategory, context: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for detector in &self.detectors {
            if detector.metadata().category == category {
                findings.extend(detector.detect(context));
            }
        }
        findings
    }
    
    pub fn get_detector(&self, id: &str) -> Option<&dyn Detector> {
        self.detectors.iter().find(|d| d.metadata().id == id).map(|d| d.as_ref())
    }
    
    pub fn list_detectors(&self) -> Vec<DetectorMetadata> {
        self.detectors.iter().map(|d| d.metadata()).collect()
    }
}
