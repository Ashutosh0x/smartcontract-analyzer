use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectType {
    Foundry,
    Hardhat,
    Bare,
    Unknown,
}

pub struct CompilerManager;

impl CompilerManager {
    /// Detect the project type by looking for config files.
    pub fn detect_project(root: &Path) -> ProjectType {
        if root.join("foundry.toml").exists() {
            ProjectType::Foundry
        } else if root.join("hardhat.config.ts").exists() || root.join("hardhat.config.js").exists() {
            ProjectType::Hardhat
        } else {
            // Check if there are any .sol files
            let has_sol = walkdir::WalkDir::new(root)
                .max_depth(5)
                .into_iter()
                .filter_map(|e| e.ok())
                .any(|e| e.path().extension().map(|ext| ext == "sol").unwrap_or(false));
            if has_sol { ProjectType::Bare } else { ProjectType::Unknown }
        }
    }
}
