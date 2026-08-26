use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct MissingGapDetector;

impl Detector for MissingGapDetector {
    fn id(&self) -> &str { "MISSING_GAP" }
    fn title(&self) -> &str { "Missing Gap in Upgradeable" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Upgradeable base without __gap variable." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for contract in &ctx.contracts {
            let is_upgradeable = contract.name.contains("Upgradeable") || contract.bases.iter().any(|b| b.contains("Upgradeable"));
            if is_upgradeable {
                let has_gap = contract.state_variables.iter().any(|&v_idx| {
                    if let Some(v) = ctx.state_variables.get(v_idx) {
                        v.name == "__gap"
                    } else { false }
                });
                if !has_gap {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: contract.loc.file.clone(),
                        line: contract.loc.start,
                        contract_name: contract.name.clone(),
                        function_name: String::new(),
                        snippet: String::new(),
                        remediation: "Add uint256[50] private __gap;".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
