use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct MultipleConstructorsDetector;

impl Detector for MultipleConstructorsDetector {
    fn id(&self) -> &str { "MULTIPLE_CONSTRUCTORS" }
    fn title(&self) -> &str { "Multiple Constructors" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Multiple constructors in a contract." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for contract in &ctx.contracts {
            let mut cons_count = 0;
            for &f_idx in &contract.functions {
                if ctx.functions[f_idx].is_constructor {
                    cons_count += 1;
                }
            }
            if cons_count > 1 {
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
                    remediation: "Remove extra constructors".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
