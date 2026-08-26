use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct SwappedShiftDetector;

impl Detector for SwappedShiftDetector {
    fn id(&self) -> &str { "SWAPPED_SHIFT" }
    fn title(&self) -> &str { "Swapped Shift Ops" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "shl or shr usage in assembly." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.has_assembly && (func.body_source.contains("shl(") || func.body_source.contains("shr(")) {
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
                    remediation: "Ensure shift parameter order is correct".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
