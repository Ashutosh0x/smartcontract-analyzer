use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct DefaultVisibilityDetector;

impl Detector for DefaultVisibilityDetector {
    fn id(&self) -> &str { "DEFAULT_VISIBILITY" }
    fn title(&self) -> &str { "Default Visibility" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Function missing explicit visibility." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.visibility == crate::context::Visibility::Default && !func.is_constructor {
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
                    snippet: func.name.clone(),
                    remediation: "Explicitly specify visibility".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
