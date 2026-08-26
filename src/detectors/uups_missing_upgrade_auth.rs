use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct UupsMissingUpgradeAuthDetector;

impl Detector for UupsMissingUpgradeAuthDetector {
    fn id(&self) -> &str { "PROXY-03" }
    fn title(&self) -> &str { "Missing UUPS _authorizeUpgrade" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "UUPSUpgradeable contract is missing _authorizeUpgrade override" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            let is_uups = contract.bases.iter().any(|b| b.contains("UUPSUpgradeable"));
            if is_uups {
                let mut has_auth = false;
                for &func_idx in &contract.functions {
                    let func = &ctx.functions[func_idx];
                    if func.name == "_authorizeUpgrade" {
                        has_auth = true;
                        break;
                    }
                }
                if !has_auth {
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
                        remediation: "Override _authorizeUpgrade to protect upgrades".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        findings
    }
}
