use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct EmptyPayableDetector;

impl Detector for EmptyPayableDetector {
    fn id(&self) -> &str { "EMPTY_PAYABLE" }
    fn title(&self) -> &str { "Empty Payable Function" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Receive or fallback is empty." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if (func.is_receive || func.is_fallback) && func.mutability == crate::context::Mutability::Payable {
                let trimmed = func.body_source.replace(" ", "").replace("\n", "");
                if trimmed == "{}" || trimmed.is_empty() {
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
                        remediation: "Ensure intention of empty payable".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
