use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct Push0CompatibilityDetector;

impl Detector for Push0CompatibilityDetector {
    fn id(&self) -> &str { "EVM-01" }
    fn title(&self) -> &str { "PUSH0 Compatibility" }
    fn severity(&self) -> Severity { Severity::Informational }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Solidity >=0.8.20 uses PUSH0 which is not supported on all L2 chains" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for source in &ctx.sources {
            for pragma in &source.pragmas {
                let ver = &pragma.version_req;
                // Check if pragma specifies >= 0.8.20 or higher
                if ver.contains("0.8.20") || ver.contains("0.8.21") || ver.contains("0.8.22")
                    || ver.contains("0.8.23") || ver.contains("0.8.24") || ver.contains("0.8.25")
                    || ver.contains("0.8.26") || ver.contains("0.8.27") || ver.contains("0.8.28")
                    || ver.contains("0.9.")
                {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: source.path.clone(),
                        line: pragma.loc.line,
                        contract_name: String::new(),
                        function_name: String::new(),
                        snippet: format!("pragma solidity {}", ver),
                        remediation: "Use evm_version = 'paris' in foundry.toml for L2 compatibility".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        findings
    }
}
