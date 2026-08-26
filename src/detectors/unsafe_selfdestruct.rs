use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct UnsafeSelfdestructDetector;

impl Detector for UnsafeSelfdestructDetector {
    fn id(&self) -> &str { "UNSAFE_SELFDESTRUCT" }
    fn title(&self) -> &str { "Unsafe Selfdestruct" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "selfdestruct without proper access control." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains("selfdestruct(") {
                let has_modifier = func.modifiers.iter().any(|m| m.contains("onlyOwner") || m.contains("onlyRole") || m.contains("auth"));
                let has_require = func.body_source.contains("require(msg.sender ==");
                if !has_modifier && !has_require {
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
                        remediation: "Protect selfdestruct with access control".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
