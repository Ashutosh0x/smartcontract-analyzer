use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct MissingDeadlineDetector;

impl Detector for MissingDeadlineDetector {
    fn id(&self) -> &str { "DEFI-02" }
    fn title(&self) -> &str { "Missing Deadline Protection" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Swap function called without deadline protection" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.body_source.contains("swap") {
                    let has_deadline_param = func.params.iter().any(|p| p.name.to_lowercase().contains("deadline") || p.type_name.to_lowercase().contains("deadline"));
                    if !has_deadline_param && !func.body_source.contains("block.timestamp") {
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
                            remediation: "Use a deadline parameter".to_string(),
                            cwe: None,
                            swc: None,
                        });
                    }
                }
            }
        }
        findings
    }
}
