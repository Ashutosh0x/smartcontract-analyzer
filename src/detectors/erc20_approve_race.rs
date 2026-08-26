use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct Erc20ApproveRaceDetector;

impl Detector for Erc20ApproveRaceDetector {
    fn id(&self) -> &str { "TOKEN-01" }
    fn title(&self) -> &str { "ERC20 Approve Race Condition" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Calls approve() without setting to 0 first" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.body_source.contains(".approve(") && !func.body_source.contains(", 0)") && !func.body_source.contains("safeApprove") {
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
                        remediation: "Use safeApprove or approve 0 first".to_string(),
                        cwe: None,
                        swc: Some("SWC-114".to_string()),
                    });
                }
            }
        }
        findings
    }
}
