use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct UnaryPlusDetector;

impl Detector for UnaryPlusDetector {
    fn id(&self) -> &str { "UNARY_PLUS" }
    fn title(&self) -> &str { "Unary Plus Typo" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "= + typo for +=." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains("=+") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: "=+".to_string(),
                    remediation: "Change to +=".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
