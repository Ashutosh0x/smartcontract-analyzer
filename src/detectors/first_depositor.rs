use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct FirstDepositorDetector;

impl Detector for FirstDepositorDetector {
    fn id(&self) -> &str { "DEFI-03" }
    fn title(&self) -> &str { "First Depositor / Inflation Attack" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "ERC4626 without decimals offset" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            let is_4626 = contract.bases.iter().any(|b| b.contains("ERC4626"));
            if is_4626 {
                let has_offset = contract.functions.iter().any(|&f_idx| {
                    let f = &ctx.functions[f_idx];
                    f.name == "_decimalsOffset"
                });
                
                if !has_offset {
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
                        remediation: "Implement virtual shares or _decimalsOffset()".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        findings
    }
}
