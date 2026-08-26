use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct ArbitraryTransferfromDetector;

impl Detector for ArbitraryTransferfromDetector {
    fn id(&self) -> &str { "ARBITRARY_TRANSFERFROM" }
    fn title(&self) -> &str { "Arbitrary TransferFrom" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "transferFrom where from parameter is user-supplied." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains(".transferFrom(") {
                let suspicious = func.params.iter().any(|p| {
                    func.body_source.contains(&format!(".transferFrom({},", p.name)) || 
                    func.body_source.contains(&format!(".transferFrom( {},", p.name))
                });
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
                        remediation: "Ensure 'from' is msg.sender".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        
        findings
    }
}
