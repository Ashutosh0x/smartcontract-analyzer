use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct DelegatecallInConstructorDetector;

impl Detector for DelegatecallInConstructorDetector {
    fn id(&self) -> &str { "PROXY-04" }
    fn title(&self) -> &str { "Delegatecall in Constructor" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Constructor contains delegatecall" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.is_constructor && func.body_source.contains(".delegatecall(") {
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
                        remediation: "Avoid using delegatecall in constructor".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        findings
    }
}
