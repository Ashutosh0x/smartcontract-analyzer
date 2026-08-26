use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct UncheckedTransferDetector;

impl Detector for UncheckedTransferDetector {
    fn id(&self) -> &str { "UNCHECKED_TRANSFER" }
    fn title(&self) -> &str { "Unchecked Transfer" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Calls to .transfer( or .transferFrom( without SafeERC20." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains(".transfer(") || func.body_source.contains(".transferFrom(") {
                let contract = &ctx.contracts[func.contract_idx];
                // basic heuristic for SafeERC20 check
                let source = &ctx.sources[contract.source_idx].source;
                if !source.contains("SafeERC20") && !func.body_source.contains("safeTransfer") {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: contract.name.clone(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Use SafeERC20".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
