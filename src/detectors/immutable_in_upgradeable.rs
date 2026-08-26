use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct ImmutableInUpgradeableDetector;

impl Detector for ImmutableInUpgradeableDetector {
    fn id(&self) -> &str { "PROXY-05" }
    fn title(&self) -> &str { "Immutable in Upgradeable" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Upgradeable contract contains immutable state variables" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            let is_up = contract.bases.iter().any(|b| b.contains("Upgradeable"));
            if is_up {
                for &sv_idx in &contract.state_variables {
                    let sv = &ctx.state_variables[sv_idx];
                    if sv.is_immutable {
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
                            snippet: sv.name.clone(),
                            remediation: "Avoid immutable in upgradeable contracts unless fully understood".to_string(),
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
