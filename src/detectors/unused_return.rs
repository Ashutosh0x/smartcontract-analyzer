use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct UnusedReturnDetector;

impl Detector for UnusedReturnDetector {
    fn id(&self) -> &str { "UNUSED_RETURN" }
    fn title(&self) -> &str { "Unused Return Value" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "Return value of a function is not checked." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            let lines: Vec<&str> = func.body_source.lines().collect();
            for line in lines {
                if line.contains('(') && line.contains(");") && !line.contains('=') && !line.contains("require") && !line.contains("if") {
                    // heuristic for a standalone call
                    if line.trim().starts_with("require") || line.trim().starts_with("assert") || line.trim().starts_with("emit ") || line.trim().starts_with("revert") {
                        continue;
                    }
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
                        snippet: line.trim().to_string(),
                        remediation: "Capture and handle the return value".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
