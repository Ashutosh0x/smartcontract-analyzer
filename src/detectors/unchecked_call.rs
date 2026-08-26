use crate::detectors::*;

pub struct UncheckedCallDetector;

impl UncheckedCallDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for UncheckedCallDetector {
    fn metadata(&self) -> DetectorMetadata {
        DetectorMetadata {
            id: "UNCHECKED-CALL-01".to_string(),
            name: "Unchecked Low-Level Call".to_string(),
            description: "Detects low-level calls where the return value is not checked.".to_string(),
            category: DetectorCategory::CodeQuality,
            severity: Severity::Medium,
            confidence: Confidence::High,
            cwe: vec!["CWE-252".to_string()],
            swc: vec!["SWC-104".to_string()],
            eip: vec![],
            affected_solidity_versions: None,
            affected_compiler_versions: None,
        }
    }

    fn detect(&self, _context: &AnalysisContext) -> Vec<Finding> {
        // TODO: Implement actual unchecked low-level call detection logic
        vec![]
    }

    fn name(&self) -> &str {
        "UncheckedCallDetector"
    }
}
