use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct MissingZeroCheckDetector;

impl Detector for MissingZeroCheckDetector {
    fn id(&self) -> &str { "MISSING_ZERO_CHECK" }
    fn title(&self) -> &str { "Missing Zero Check" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Missing address(0) check in initializer." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.is_constructor || func.name == "initialize" {
                let has_address_param = func.params.iter().any(|p| p.type_name.contains("address"));
                if has_address_param {
                    let has_check = func.body_source.contains("!= address(0)") || func.body_source.contains("!= address(0x0)");
                    if !has_check {
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
                            remediation: "Add require checks for address(0)".to_string(),
                            cwe: None,
                            swc: None,
                        });
                    }
                }
            }
        }
        
        findings
    }
}
