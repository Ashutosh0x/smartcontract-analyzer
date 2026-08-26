use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct StructMappingDeleteDetector;

impl Detector for StructMappingDeleteDetector {
    fn id(&self) -> &str { "STRUCT_MAPPING_DELETE" }
    fn title(&self) -> &str { "Struct Mapping Delete" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "Deleting a struct containing a mapping leaves the mapping intact." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.body_source.contains("delete ") {
                // Since full type inference isn't available, report all deletes as warning.
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
                    remediation: "Ensure the struct does not contain mappings".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
