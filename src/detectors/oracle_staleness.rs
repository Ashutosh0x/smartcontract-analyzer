use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct OracleStalenessDetector;

impl Detector for OracleStalenessDetector {
    fn id(&self) -> &str { "ORACLE-01" }
    fn title(&self) -> &str { "Missing Staleness Check" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Calls latestRoundData() but does not check updatedAt" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.body_source.contains("latestRoundData()") {
                    if !func.body_source.contains("updatedAt") && !func.body_source.contains("answeredInRound") {
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
                            remediation: "Check updatedAt from latestRoundData()".to_string(),
                            cwe: Some("CWE-754".to_string()),
                            swc: None,
                        });
                    }
                }
            }
        }
        findings
    }
}
