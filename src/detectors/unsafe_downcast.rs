use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct UnsafeDowncastDetector;

impl Detector for UnsafeDowncastDetector {
    fn id(&self) -> &str { "UNSAFE_DOWNCAST" }
    fn title(&self) -> &str { "Unsafe Downcast" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Unsafe integer downcast." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            let casts = ["uint128(", "uint64(", "uint32(", "uint16(", "uint8("];
            for c in casts {
                if func.body_source.contains(c) && !func.body_source.contains("SafeCast") {
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
                        remediation: "Use SafeCast library".to_string(),
                        cwe: None,
                        swc: None,
                    });
                    break;
                }
            }
        }
        
        findings
    }
}
