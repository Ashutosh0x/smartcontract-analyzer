use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct ArbitraryDelegatecallDetector;

impl Detector for ArbitraryDelegatecallDetector {
    fn id(&self) -> &str { "ARBITRARY_DELEGATECALL" }
    fn title(&self) -> &str { "Arbitrary Delegatecall" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "delegatecall with user-controlled target." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains(".delegatecall(") {
                // Heuristic: check if any param name is used near .delegatecall
                let suspicious = func.params.iter().any(|p| func.body_source.contains(&format!("{}.delegatecall", p.name)));
                if suspicious {
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
                        remediation: "Do not allow user-controlled delegatecall target".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
