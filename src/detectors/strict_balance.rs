use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct StrictBalanceDetector;

impl Detector for StrictBalanceDetector {
    fn id(&self) -> &str { "STRICT_BALANCE" }
    fn title(&self) -> &str { "Strict Balance Equality" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Checking address(this).balance exactly." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains("address(this).balance ==") {
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
                    snippet: func.body_source.clone(),
                    remediation: "Use >= instead of ==".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
