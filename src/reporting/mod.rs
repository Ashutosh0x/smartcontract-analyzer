use chrono::{DateTime, Utc};
use std::time::Duration;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReportFormat {
    Terminal,
    Json,
    Sarif,
    Markdown,
    Html,
}

#[derive(Debug, Clone, Serialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: RiskLevel,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityScore {
    pub total: u32,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub attack_surface: RiskLevel,
    pub centralization_risk: RiskLevel,
    pub upgrade_risk: RiskLevel,
    pub oracle_risk: RiskLevel,
    pub dependency_risk: RiskLevel,
    pub compiler_risk: RiskLevel,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub files_scanned: usize,
    pub lines_of_code: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerInfo {
    pub version: String,
    pub framework: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityReport {
    pub project_name: String,
    pub scan_timestamp: DateTime<Utc>,
    pub scan_duration: Duration,
    pub findings: Vec<Finding>,
    pub security_score: SecurityScore,
    pub summary: ReportSummary,
    pub compiler_info: CompilerInfo,
}

impl SecurityReport {
    pub fn generate(&self, format: ReportFormat) -> Result<String, anyhow::Error> {
        match format {
            ReportFormat::Terminal => self.to_terminal(),
            ReportFormat::Json => self.to_json(),
            ReportFormat::Sarif => self.to_sarif(),
            ReportFormat::Markdown => self.to_markdown(),
            ReportFormat::Html => todo!("HTML report generation not implemented"),
        }
    }

    pub fn to_json(&self) -> Result<String, anyhow::Error> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn to_sarif(&self) -> Result<String, anyhow::Error> {
        let mut results = vec![];

        for finding in &self.findings {
            let result = serde_json::json!({
                "ruleId": finding.id,
                "message": { "text": finding.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.file },
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
                        "informationUri": "https://example.com/sentinel",
                        "rules": []
                    }
                },
                "results": results
            }]
        });

        serde_json::to_string_pretty(&sarif).map_err(Into::into)
    }

    pub fn to_markdown(&self) -> Result<String, anyhow::Error> {
        let mut md = format!("# Security Report for {}\n\n", self.project_name);
        md.push_str(&format!("**Scan Time:** {}\n", self.scan_timestamp));
        md.push_str(&format!("**Duration:** {:?}\n\n", self.scan_duration));
        md.push_str(&format!("## Score: {}/100\n\n", self.security_score.total));
        
        md.push_str("## Findings\n\n");
        for finding in &self.findings {
            md.push_str(&format!("### [{}] {}\n", finding.id, finding.title));
            md.push_str(&format!("**Severity:** {:?}\n", finding.severity));
            md.push_str(&format!("**File:** {}:{}\n\n", finding.file, finding.line));
            md.push_str(&format!("{}\n\n", finding.description));
        }

        Ok(md)
    }

    pub fn to_terminal(&self) -> Result<String, anyhow::Error> {
        let mut out = format!("Report for {}\n", self.project_name);
        out.push_str(&format!("Score: {}/100\n", self.security_score.total));
        for finding in &self.findings {
            out.push_str(&format!("- [{:?}] {}: {} ({}:{})\n", finding.severity, finding.id, finding.title, finding.file, finding.line));
        }
        Ok(out)
    }

    pub fn calculate_score(findings: &[Finding]) -> SecurityScore {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for finding in findings {
            match finding.severity {
                RiskLevel::Critical => critical_count += 1,
                RiskLevel::High => high_count += 1,
                RiskLevel::Medium => medium_count += 1,
                RiskLevel::Low => low_count += 1,
                RiskLevel::Info => info_count += 1,
                RiskLevel::None => {}
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
            info_count,
            attack_surface: RiskLevel::None,
            centralization_risk: RiskLevel::None,
            upgrade_risk: RiskLevel::None,
            oracle_risk: RiskLevel::None,
            dependency_risk: RiskLevel::None,
            compiler_risk: RiskLevel::None,
        }
    }
}
