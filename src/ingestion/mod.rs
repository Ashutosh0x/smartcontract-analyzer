use std::path::{Path, PathBuf};
use crate::compiler::{CompilerManager, ProjectType};
use crate::SentinelError;

#[derive(Debug)]
pub struct DiscoveredProject {
    pub root: PathBuf,
    pub project_type: ProjectType,
    pub source_files: Vec<PathBuf>,
    pub remappings: Vec<String>,
}

pub struct ProjectDiscoverer;

impl ProjectDiscoverer {
    pub fn discover(root: &Path) -> Result<DiscoveredProject, SentinelError> {
        let project_type = CompilerManager::detect_project(root);
        let (src_dirs, exclude_dirs) = match &project_type {
            ProjectType::Foundry => {
                // Parse foundry.toml for src dir
                let src = Self::parse_foundry_src(root).unwrap_or_else(|| "src".to_string());
                (vec![src], vec!["test", "script", "lib"])
            }
            ProjectType::Hardhat => {
                (vec!["contracts".to_string()], vec!["node_modules", "artifacts", "cache"])
            }
            ProjectType::Bare => {
                (vec![".".to_string()], vec!["node_modules", "lib", ".git"])
            }
            ProjectType::Unknown => {
                (vec![".".to_string()], vec!["node_modules", ".git"])
            }
        };

        let mut source_files = Vec::new();
        for src_dir in &src_dirs {
            let search_root = root.join(src_dir);
            if search_root.exists() {
                for entry in walkdir::WalkDir::new(&search_root)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let path = entry.path();
                    // Skip excluded directories
                    let skip = exclude_dirs.iter().any(|ex| {
                        path.components().any(|c| c.as_os_str() == *ex)
                    });
                    if skip { continue; }
                    if path.extension().map(|e| e == "sol").unwrap_or(false) {
                        source_files.push(path.to_path_buf());
                    }
                }
            }
        }

        // Also pick up .sol files in root if Bare project
        if project_type == ProjectType::Bare && source_files.is_empty() {
            for entry in walkdir::WalkDir::new(root)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                let skip = exclude_dirs.iter().any(|ex| {
                    path.components().any(|c| c.as_os_str() == *ex)
                });
                if skip { continue; }
                if path.extension().map(|e| e == "sol").unwrap_or(false) {
                    source_files.push(path.to_path_buf());
                }
            }
        }

        // Read remappings if they exist
        let remappings = Self::read_remappings(root);

        Ok(DiscoveredProject {
            root: root.to_path_buf(),
            project_type,
            source_files,
            remappings,
        })
    }

    fn parse_foundry_src(root: &Path) -> Option<String> {
        let toml_path = root.join("foundry.toml");
        let content = std::fs::read_to_string(toml_path).ok()?;
        let table: toml::Table = content.parse().ok()?;
        table.get("profile")?
            .get("default")?
            .get("src")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn read_remappings(root: &Path) -> Vec<String> {
        let remappings_file = root.join("remappings.txt");
        if let Ok(content) = std::fs::read_to_string(remappings_file) {
            content.lines()
                .filter(|l| !l.trim().is_empty() && l.contains('='))
                .map(|l| l.trim().to_string())
                .collect()
        } else {
            Vec::new()
        }
    }
}
