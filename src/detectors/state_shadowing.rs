use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct StateShadowingDetector;

impl Detector for StateShadowingDetector {
    fn id(&self) -> &str { "STATE_SHADOWING" }
    fn title(&self) -> &str { "State Variable Shadowing" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "State variable shadows base contract variable." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for contract in &ctx.contracts {
            let mut base_vars = std::collections::HashSet::new();
            for base_name in &contract.bases {
                if let Some(base_contract) = ctx.contracts.iter().find(|c| c.name == *base_name) {
                    for &var_idx in &base_contract.state_variables {
                        if let Some(v) = ctx.state_variables.get(var_idx) {
                            base_vars.insert(v.name.clone());
                        }
                    }
                }
            }
            for &var_idx in &contract.state_variables {
                if let Some(v) = ctx.state_variables.get(var_idx) {
                    if base_vars.contains(&v.name) {
                        findings.push(Finding {
                            detector_id: self.id().to_string(),
                            title: self.title().to_string(),
                            description: self.description().to_string(),
                            severity: self.severity(),
                            confidence: self.confidence(),
                            file: v.loc.file.clone(),
                            line: v.loc.start,
                            contract_name: contract.name.clone(),
                            function_name: String::new(),
                            snippet: v.name.clone(),
                            remediation: "Rename shadowed variable".to_string(),
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
