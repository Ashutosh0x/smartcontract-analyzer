use crate::context::WorkspaceContext;
use crate::detectors::{Detector, Finding, Severity, Confidence};
use std::path::PathBuf;

pub struct SingleOracleDetector;

impl Detector for SingleOracleDetector {
    fn id(&self) -> &str { "ORACLE-03" }
    fn title(&self) -> &str { "Single Oracle Fallback" }
    fn severity(&self) -> Severity { Severity::Low }
    fn confidence(&self) -> Confidence { Confidence::Low }
    fn description(&self) -> &str { "Calls latestRoundData() but no fallback oracle detected" }
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &ctx.contracts {
            let mut oracle_count = 0;
            for &sv_idx in &contract.state_variables {
                let sv = &ctx.state_variables[sv_idx];
                let name = sv.name.to_lowercase();
                if name.contains("oracle") || name.contains("feed") || name.contains("price") {
                    oracle_count += 1;
                }
            }
            
            if oracle_count == 1 {
                for &func_idx in &contract.functions {
                    let func = &ctx.functions[func_idx];
                    if func.body_source.contains("latestRoundData()") {
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
                            remediation: "Consider implementing a fallback oracle".to_string(),
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
