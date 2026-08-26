use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct AbiEncodePackedDetector;

impl Detector for AbiEncodePackedDetector {
    fn id(&self) -> &str { "ABI_ENCODE_PACKED" }
    fn title(&self) -> &str { "abi.encodePacked with Dynamics" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "abi.encodePacked can lead to hash collisions." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains("abi.encodePacked(") && func.body_source.contains(",") {
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
                    snippet: "abi.encodePacked".to_string(),
                    remediation: "Use abi.encode() instead if packing multiple dynamic parameters".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
