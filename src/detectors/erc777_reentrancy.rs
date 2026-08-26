use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct Erc777ReentrancyDetector;

impl Detector for Erc777ReentrancyDetector {
    fn id(&self) -> &str { "TOKEN-02" }
    fn title(&self) -> &str { "ERC777 Reentrancy" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "Contract handles ERC777 callbacks which can lead to reentrancy" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            let is_recipient = contract.bases.iter().any(|b| b.contains("IERC777Recipient"));
            let mut found = is_recipient;
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.body_source.contains("tokensReceived") || func.body_source.contains("tokensToSend") {
                    found = true;
                }
            }
            if found {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: PathBuf::from(""),
                    line: 0,
                    contract_name: contract.name.clone(),
                    function_name: "".to_string(),
                    snippet: "".to_string(),
                    remediation: "Add reentrancy guards to functions handling tokens".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        findings
    }
}
