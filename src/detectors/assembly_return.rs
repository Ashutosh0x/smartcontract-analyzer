use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct AssemblyReturnDetector;

impl Detector for AssemblyReturnDetector {
    fn id(&self) -> &str { "ASSEMBLY_RETURN" }
    fn title(&self) -> &str { "Assembly Return" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn description(&self) -> &str { "Return inside assembly instead of leave." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.has_assembly && func.body_source.contains("return(") {
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
                    snippet: "return(".to_string(),
                    remediation: "Use 'leave' or 'return' properly".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
