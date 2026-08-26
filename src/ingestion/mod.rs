use std::path::{Path, PathBuf};

pub struct ProjectDiscoverer;

impl ProjectDiscoverer {
    pub fn find_sol_files(_dir: &Path) -> Result<Vec<PathBuf>, anyhow::Error> {
        todo!("Walk directory and find .sol files")
    }

    pub fn parse_config(_dir: &Path) -> Result<(), anyhow::Error> {
        todo!("Parse foundry.toml or hardhat.config")
    }
}
