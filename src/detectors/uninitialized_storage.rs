use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct UninitializedStorageDetector;

impl Detector for UninitializedStorageDetector {
    fn id(&self) -> &str { "UNINITIALIZED_STORAGE" }
    fn title(&self) -> &str { "Uninitialized Storage" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "Local variable declared as storage but not initialized." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains(" storage ") && !func.body_source.contains(" = ") {
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
                    remediation: "Initialize storage pointers".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
