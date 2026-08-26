use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct LockedEtherDetector;

impl Detector for LockedEtherDetector {
    fn id(&self) -> &str { "LOCKED_ETHER" }
    fn title(&self) -> &str { "Locked Ether" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Contract accepts ether but cannot send it." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for contract in &ctx.contracts {
            let mut has_payable = false;
            let mut can_send = false;
            for &f_idx in &contract.functions {
                let f = &ctx.functions[f_idx];
                if f.is_receive || f.is_fallback || f.mutability == crate::context::Mutability::Payable {
                    has_payable = true;
                }
                if f.body_source.contains(".transfer(") || f.body_source.contains(".send(") || f.body_source.contains(".call{value:") {
                    can_send = true;
                }
            }
            if has_payable && !can_send {
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
                    remediation: "Implement a way to withdraw ether".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
