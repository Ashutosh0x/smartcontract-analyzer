use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct UnprotectedInitializerDetector;

impl Detector for UnprotectedInitializerDetector {
    fn id(&self) -> &str { "PROXY-01" }
    fn title(&self) -> &str { "Unprotected Initializer" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Initializer function is not protected by initializer modifier" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                let fname = func.name.to_lowercase();
                if fname == "initialize" || fname == "initialise" || fname == "init" {
                    let has_mod = func.modifiers.iter().any(|m| m.to_lowercase() == "initializer");
                    if !has_mod {
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
                            remediation: "Add the initializer modifier".to_string(),
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
