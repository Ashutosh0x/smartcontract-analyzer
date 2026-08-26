use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};

pub struct MsgValueLoopDetector;

impl Detector for MsgValueLoopDetector {
    fn id(&self) -> &str { "MSG_VALUE_LOOP" }
    fn title(&self) -> &str { "Msg.value in Loop" }
    fn severity(&self) -> Severity { Severity::High }
    fn confidence(&self) -> Confidence { Confidence::Medium }
    fn description(&self) -> &str { "msg.value used inside a loop." }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in &ctx.functions {
            if func.has_loops && func.body_source.contains("msg.value") {
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
                    remediation: "Avoid using msg.value inside loops".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        
        findings
    }
}
