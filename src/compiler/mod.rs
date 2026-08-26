use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectType {
    Foundry,
    Hardhat,
    Standalone,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CompilationConfig {
    pub solc_version: Option<semver::Version>,
    pub via_ir: bool,
    pub optimizer: bool,
    pub optimizer_runs: u32,
    pub remappings: Vec<String>,
    pub libraries: HashMap<String, String>,
    pub evm_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerDiagnostic {
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub id: u32,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct CompilationResult {
    pub ast: serde_json::Value,
    pub errors: Vec<CompilerDiagnostic>,
    pub warnings: Vec<CompilerDiagnostic>,
    pub sources: HashMap<String, SourceInfo>,
}

#[derive(Debug, Clone)]
pub struct CompilerBug {
    pub id: String,
    pub description: String,
}

#[allow(dead_code)]
pub struct CompilerManager {
    solc_path: Option<PathBuf>,
    detected_version: Option<semver::Version>,
    project_type: ProjectType,
}

impl CompilerManager {
    pub fn new() -> Self {
        Self {
            solc_path: None,
            detected_version: None,
            project_type: ProjectType::Unknown,
        }
    }

    pub fn detect_project(path: &Path) -> ProjectType {
        if path.join("foundry.toml").exists() {
            ProjectType::Foundry
        } else if path.join("hardhat.config.js").exists() || path.join("hardhat.config.ts").exists() {
            ProjectType::Hardhat
        } else if path.join("src").exists() || path.join("contracts").exists() {
            ProjectType::Standalone
        } else {
            ProjectType::Unknown
        }
    }

    pub fn detect_solc_version(_source: &str) -> Option<semver::VersionReq> {
        todo!("Parse pragma solidity")
    }

    pub fn compile(_config: &CompilationConfig, _sources: &[PathBuf]) -> Result<CompilationResult, anyhow::Error> {
        todo!("Invoke solc and parse output")
    }

    pub fn check_known_bugs(_version: &semver::Version) -> Vec<CompilerBug> {
        todo!("Check against known compiler bugs database")
    }
}
