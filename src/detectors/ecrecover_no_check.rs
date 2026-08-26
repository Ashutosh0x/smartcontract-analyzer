use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct EcrecoverNoCheckDetector;

impl Detector for EcrecoverNoCheckDetector {
    fn id(&self) -> &str { "CRYPTO-01" }
    fn title(&self) -> &str { "ecrecover Without Null Check" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "ecrecover result is not checked against address(0)" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.body_source.contains("ecrecover(") {
                    if !func.body_source.contains("!= address(0)") {
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
                            remediation: "Check that ecrecover result is not address(0)".to_string(),
                            cwe: Some("CWE-347".to_string()),
                            swc: Some("SWC-117".to_string()),
                        });
                    }
                }
            }
        }
        findings
    }
}
