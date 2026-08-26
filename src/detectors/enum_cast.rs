use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct EnumCastDetector;

impl Detector for EnumCastDetector {
    fn id(&self) -> &str { "ENUM_CAST" }
    fn title(&self) -> &str { "Unsafe Enum Cast" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "Explicit enum type cast." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            // Very simple heuristic for explicit cast
            if func.body_source.contains(")(") {
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
                    remediation: "Validate bounds when casting to enum".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
