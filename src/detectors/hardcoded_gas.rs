use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;
use regex::Regex;

pub struct HardcodedGasDetector;

impl Detector for HardcodedGasDetector {
    fn id(&self) -> &str { "GAS-02" }
    fn title(&self) -> &str { "Hardcoded Gas" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Hardcoded gas amounts can change across hard forks" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let re = Regex::new(r"\.call\{.*gas:\s*\d+").unwrap();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if re.is_match(&func.body_source) {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: PathBuf::from(""),
                        line: 0,
                        contract_name: contract.name.clone(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Avoid hardcoding gas values".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        findings
    }
}
