use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct MissingNonceDetector;

impl Detector for MissingNonceDetector {
    fn id(&self) -> &str { "CRYPTO-02" }
    fn title(&self) -> &str { "Missing Nonce in Signature" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "Signature verification used but no nonce state variable found" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            let has_nonce = contract.state_variables.iter().any(|&sv_idx| {
                let sv = &ctx.state_variables[sv_idx];
                sv.name.to_lowercase().contains("nonce")
            });
            
            if !has_nonce {
                for &func_idx in &contract.functions {
                    let func = &ctx.functions[func_idx];
                    if func.body_source.contains("ecrecover(") {
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
                            remediation: "Use a nonce to prevent signature replay attacks".to_string(),
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
