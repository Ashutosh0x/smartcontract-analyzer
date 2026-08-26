use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct BlockRandomnessDetector;

impl Detector for BlockRandomnessDetector {
    fn id(&self) -> &str { "BLOCK_RANDOMNESS" }
    fn title(&self) -> &str { "Block Randomness" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Using block variables for randomness." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            let triggers = ["block.timestamp", "blockhash(", "block.difficulty", "block.prevrandao"];
            for t in triggers {
                if func.body_source.contains(t) {
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
                        remediation: "Use secure randomness (e.g. Chainlink VRF)".to_string(),
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
