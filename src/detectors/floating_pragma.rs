use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct FloatingPragmaDetector;

impl Detector for FloatingPragmaDetector {
    fn id(&self) -> &str { "FLOATING_PRAGMA" }
    fn title(&self) -> &str { "Floating Pragma" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Source uses a floating pragma." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for src in &ctx.sources {
            if let Some(idx) = src.source.find("pragma solidity") {
                let end = src.source[idx..].find(';').unwrap_or(src.source.len() - idx);
                let pragma_stmt = &src.source[idx..idx+end];
                if pragma_stmt.contains('^') || pragma_stmt.contains(">=") {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: src.path.clone(),
                        line: 0,
                        contract_name: String::new(),
                        function_name: String::new(),
                        snippet: pragma_stmt.to_string(),
                        remediation: "Pin the pragma version".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
