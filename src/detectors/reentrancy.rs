use crate::detectors::*;

pub struct ReentrancyDetector;

impl ReentrancyDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for ReentrancyDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "REENTRANCY-01".to_string(),
            name: "Reentrancy Vulnerability".to_string(),
            description: "Detects state changes after an external call.".to_string(),
            category: DetectorCategory::Reentrancy,
            severity: Severity::High,
            confidence: Confidence::Medium,
            cwe: vec!["CWE-841".to_string()],
            swc: vec!["SWC-107".to_string()],
            eip: vec![],
            affected_solidity_versions: None,
            affected_compiler_versions: None,
        }
    }

    fn detect(&self, _context: &AnalysisContext) -> Vec<Finding> {
        // TODO: Implement actual reentrancy detection logic:
        // - Looks for external calls followed by state variable writes
        // - Tracks reentrancy guard modifiers
        // - Distinguishes cross-function reentrancy
        // - Produces evidence with data flow steps
        vec![]
    }

    fn name(&self) -> &str {
        "ReentrancyDetector"
    }
}
