use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct DivisionBeforeMultiplyDetector;

impl Detector for DivisionBeforeMultiplyDetector {
    fn id(&self) -> &str { "DIVISION_BEFORE_MULTIPLY" }
    fn title(&self) -> &str { "Division Before Multiply" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Division operation appears before multiplication." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            let parts: Vec<&str> = func.body_source.split(';').collect();
            for part in parts {
                if let Some(div_pos) = part.find('/') {
                    if let Some(mul_pos) = part.find('*') {
                        if div_pos < mul_pos {
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
                                snippet: part.to_string(),
                                remediation: "Multiply before dividing to avoid precision loss".to_string(),
                                cwe: None,
                                swc: None,
                            });
                        }
                    }
                }
            }
        }
        
        findings
    }
}
