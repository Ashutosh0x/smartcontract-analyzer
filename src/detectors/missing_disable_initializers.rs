use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct MissingDisableInitializersDetector;

impl Detector for MissingDisableInitializersDetector {
    fn id(&self) -> &str { "PROXY-02" }
    fn title(&self) -> &str { "Missing _disableInitializers" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Constructor of initializable contract does not call _disableInitializers()" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            let is_init = contract.bases.iter().any(|b| b.contains("Initializable") || b.contains("Upgradeable"));
            if is_init {
                for &func_idx in &contract.functions {
                    let func = &ctx.functions[func_idx];
                    if func.is_constructor {
                        if !func.body_source.contains("_disableInitializers()") {
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
                                remediation: "Add _disableInitializers() to constructor".to_string(),
                                cwe: None,
                                swc: None,
                            });
                        }
                    }
                }
            }
        }
        findings
    }
}
