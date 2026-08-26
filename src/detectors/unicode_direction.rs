use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct UnicodeDirectionDetector;

impl Detector for UnicodeDirectionDetector {
    fn id(&self) -> &str { "UNICODE_DIRECTION" }
    fn title(&self) -> &str { "Unicode Direction Override" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Contains unicode direction override chars." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for src in &ctx.sources {
            let malicious_chars = ["\u{202E}", "\u{202D}", "\u{202C}"];
            for mc in malicious_chars {
                if src.source.contains(mc) {
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
                        snippet: String::new(),
                        remediation: "Remove bidirectional unicode characters".to_string(),
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
