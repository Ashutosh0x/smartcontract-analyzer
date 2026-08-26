use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct CostlyLoopSloadDetector;

impl Detector for CostlyLoopSloadDetector {
    fn id(&self) -> &str { "GAS-01" }
    fn title(&self) -> &str { "Costly Loop SLOAD" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "State variable read inside a loop" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.has_loops {
                    for &sv_idx in &contract.state_variables {
                        let sv = &ctx.state_variables[sv_idx];
                        if func.body_source.contains(&sv.name) {
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
                                remediation: "Cache state variables in memory before the loop".to_string(),
                                cwe: None,
                                swc: None,
                            });
                            break;
                        }
                    }
                }
            }
        }
        findings
    }
}
