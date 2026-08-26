use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct MissingSlippageDetector;

impl Detector for MissingSlippageDetector {
    fn id(&self) -> &str { "DEFI-01" }
    fn title(&self) -> &str { "Missing Slippage Protection" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Swap function called without slippage protection" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.body_source.contains("swap(") || func.body_source.contains("swapExact") {
                    if !func.body_source.contains("amountOutMin") && !func.body_source.contains("minAmountOut") && !func.body_source.contains("minReturn") {
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
                            remediation: "Add a minimum return amount check".to_string(),
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
