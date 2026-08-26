use serde::{Serialize, Deserialize};
use comfy_table::{Table, Cell, Color as ComfyColor, Attribute};
use colored::Colorize;
use crate::detectors::{Severity, Finding};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Terminal,
    Json,
    Sarif,
    Markdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    pub total: u32,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub informational_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub project_name: String,
    pub findings: Vec<Finding>,
    pub security_score: SecurityScore,
}

impl SecurityReport {
    pub fn new(project_name: String, findings: Vec<Finding>) -> Self {
        let security_score = Self::calculate_score(&findings);
        Self { project_name, findings, security_score }
    }

    pub fn generate(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Terminal => self.to_terminal(),
            ReportFormat::Json => self.to_json(),
            ReportFormat::Sarif => self.to_sarif(),
            ReportFormat::Markdown => self.to_markdown(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn to_sarif(&self) -> String {
        let mut results = vec![];
        for finding in &self.findings {
            let result = serde_json::json!({
                "ruleId": finding.detector_id,
                "message": { "text": finding.title.clone() },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.file.to_string_lossy() },
                        "region": { "startLine": finding.line }
                    }
                }]
            });
            results.push(result);
        }

        let sarif = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "rules": []
                    }
                },
                "results": results
            }]
        });
        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    }

    pub fn to_markdown(&self) -> String {
        let mut md = format!("# Security Report for {}\n\n", self.project_name);
        md.push_str(&format!("## Score: {}/100\n\n", self.security_score.total));
        
        md.push_str("## Findings\n\n");
        for finding in &self.findings {
            md.push_str(&format!("### [{}] {}\n", finding.detector_id, finding.title));
            md.push_str(&format!("**Severity:** {:?} | **Confidence:** {:?}\n", finding.severity, finding.confidence));
            md.push_str(&format!("**Location:** `{}:{}` (Contract: {}, Function: {})\n\n", finding.file.to_string_lossy(), finding.line, finding.contract_name, finding.function_name));
            md.push_str(&format!("{}\n\n", finding.description));
            md.push_str(&format!("**Remediation:** {}\n\n", finding.remediation));
        }
        md
    }

    pub fn to_terminal(&self) -> String {
        let mut out = format!("{}\n", format!("Report for {}", self.project_name).bold());
        out.push_str(&format!("Score: {}/100\n\n", self.security_score.total));
        
        if self.findings.is_empty() {
            out.push_str(&"No vulnerabilities found!\n".green().to_string());
            return out;
        }

        let mut table = Table::new();
        table.set_header(vec!["ID", "Title", "Severity", "Location"]);
        
        for finding in &self.findings {
            let sev = match finding.severity {
                Severity::Critical => Cell::new("Critical").fg(ComfyColor::Red).add_attribute(Attribute::Bold),
                Severity::High => Cell::new("High").fg(ComfyColor::Red),
                Severity::Medium => Cell::new("Medium").fg(ComfyColor::Yellow),
                Severity::Low => Cell::new("Low").fg(ComfyColor::Blue),
                Severity::Informational => Cell::new("Info").fg(ComfyColor::DarkGrey),
            };
            
            table.add_row(vec![
                Cell::new(&finding.detector_id),
                Cell::new(&finding.title),
                sev,
                Cell::new(format!("{}:{}", finding.file.to_string_lossy(), finding.line)),
            ]);
        }
        out.push_str(&table.to_string());
        out.push('\n');
        out
    }

    pub fn calculate_score(findings: &[Finding]) -> SecurityScore {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut informational_count = 0;

        for finding in findings {
            match finding.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
                Severity::Informational => informational_count += 1,
            }
        }

        let penalty = (critical_count * 20) + (high_count * 10) + (medium_count * 5) + (low_count * 1);
        let total = 100u32.saturating_sub(penalty as u32);

        SecurityScore {
            total,
            critical_count,
            high_count,
            medium_count,
            low_count,
            informational_count,
        }
    }
}
