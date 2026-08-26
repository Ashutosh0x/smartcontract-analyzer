use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct BooleanConstantComparisonDetector;

impl Detector for BooleanConstantComparisonDetector {
    fn id(&self) -> &str { "QUALITY-01" }
    fn title(&self) -> &str { "Boolean Constant Comparison" }
    fn severity(&self) -> Severity { Severity::Informational }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Unnecessary comparison to boolean constant" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if func.body_source.contains("== true") || func.body_source.contains("== false") {
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
                        remediation: "Use if (x) or if (!x) instead".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        findings
    }
}
