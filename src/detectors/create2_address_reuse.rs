use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct Create2AddressReuseDetector;

impl Detector for Create2AddressReuseDetector {
    fn id(&self) -> &str { "EVM-02" }
    fn title(&self) -> &str { "CREATE2 Address Reuse" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "Contract uses CREATE2 and selfdestruct" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            for &func_idx in &contract.functions {
                let func = &ctx.functions[func_idx];
                if (func.body_source.contains("create2(") || func.body_source.contains("CREATE2")) && func.body_source.contains("selfdestruct") {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: PathBuf::from(""),
                        line: 0,
                        contract_name: contract.name.clone(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Ensure CREATE2 with selfdestruct does not lead to unwanted address reuse".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        findings
    }
}
