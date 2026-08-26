//! Solidity AST parsing via `solang-parser`.
//!
//! This module parses Solidity source files into a structured AST
//! representation that detectors can traverse.

use std::path::{Path, PathBuf};
use solang_parser::pt;
use solang_parser::parse as solang_parse;

/// A parsed Solidity source file.
#[derive(Debug, Clone)]
pub struct ParsedSource {
    /// Path to the source file.
    pub path: PathBuf,
    /// Raw source code.
    pub source: String,
    /// Parsed AST (solang SourceUnit).
    pub tree: pt::SourceUnit,
    /// Pragma directives found in this file.
    pub pragmas: Vec<PragmaInfo>,
    /// Import directives.
    pub imports: Vec<ImportInfo>,
}

/// Information about a pragma directive.
#[derive(Debug, Clone)]
pub struct PragmaInfo {
    pub loc: Loc,
    pub version_req: String,
}

/// Information about an import directive.
#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub loc: Loc,
    pub path: String,
}

/// Source location.
#[derive(Debug, Clone, Default)]
pub struct Loc {
    pub file: PathBuf,
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

impl Loc {
    pub fn from_pt(loc: pt::Loc, source: &str, file: &Path) -> Self {
        match loc {
            pt::Loc::File(_, start, end) => {
                let (line, column) = offset_to_line_col(source, start);
                Self {
                    file: file.to_path_buf(),
                    start,
                    end,
                    line,
                    column,
                }
            }
            _ => Self {
                file: file.to_path_buf(),
                ..Default::default()
            },
        }
    }
}

/// Convert a byte offset into (line, column), both 1-indexed.
fn offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Parse a Solidity source file into a `ParsedSource`.
pub fn parse_solidity(source: &str, path: &Path) -> Result<ParsedSource, String> {
    let (tree, diagnostics) = match solang_parse(source, 0) {
        Ok((tree, _)) => (tree, vec![]),
        Err(diags) => (pt::SourceUnit(vec![]), diags),
    };

    // Collect errors (not warnings) from diagnostics
    let errors: Vec<_> = diagnostics
        .iter()
        .filter(|d| d.level == solang_parser::diagnostics::Level::Error)
        .collect();

    if !errors.is_empty() && tree.0.is_empty() {
        return Err(format!(
            "Parse errors in {:?}: {}",
            path,
            errors.iter().map(|e| e.message.as_str()).collect::<Vec<_>>().join("; ")
        ));
    }

    // Extract pragma and import info from top-level parts
    let mut pragmas = Vec::new();
    let mut imports = Vec::new();

    for part in &tree.0 {
        match part {
            pt::SourceUnitPart::PragmaDirective(pragma_box) => {
                match pragma_box.as_ref() {
                    pt::PragmaDirective::Version(loc, _ident, comparators) => {
                        let ver = comparators.iter().map(|c| match c {
                            pt::VersionComparator::Plain { version, .. } => version.join("."),
                            pt::VersionComparator::Operator { version, .. } => version.join("."),
                            pt::VersionComparator::Range { from, to, .. } => {
                                format!("{} - {}", from.join("."), to.join("."))
                            }
                            pt::VersionComparator::Or { left, right, .. } => {
                                format!("{:?} || {:?}", left, right)
                            }
                        }).collect::<Vec<_>>().join(" ");
                        pragmas.push(PragmaInfo {
                            loc: Loc::from_pt(*loc, source, path),
                            version_req: ver,
                        });
                    }
                    pt::PragmaDirective::Identifier(loc, _, _) => {
                        pragmas.push(PragmaInfo {
                            loc: Loc::from_pt(*loc, source, path),
                            version_req: String::new(),
                        });
                    }
                    pt::PragmaDirective::StringLiteral(loc, _, _) => {
                        pragmas.push(PragmaInfo {
                            loc: Loc::from_pt(*loc, source, path),
                            version_req: String::new(),
                        });
                    }
                }
            }
            pt::SourceUnitPart::ImportDirective(import) => {
                let import_path = match import {
                    pt::Import::Plain(ip, _loc) => extract_import_path(&ip),
                    pt::Import::GlobalSymbol(ip, _, _loc) => extract_import_path(&ip),
                    pt::Import::Rename(ip, _, _loc) => extract_import_path(&ip),
                };
                let loc = match import {
                    pt::Import::Plain(_, loc) => *loc,
                    pt::Import::GlobalSymbol(_, _, loc) => *loc,
                    pt::Import::Rename(_, _, loc) => *loc,
                };
                imports.push(ImportInfo {
                    loc: Loc::from_pt(loc, source, path),
                    path: import_path,
                });
            }
            _ => {}
        }
    }

    Ok(ParsedSource {
        path: path.to_path_buf(),
        source: source.to_string(),
        tree,
        pragmas,
        imports,
    })
}

fn extract_import_path(ip: &pt::ImportPath) -> String {
    match ip {
        pt::ImportPath::Filename(lit) => lit.string.clone(),
        pt::ImportPath::Path(path) => path.identifiers.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_contract() {
        let source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract Counter {
                uint256 public count;

                function increment() external {
                    count += 1;
                }
            }
        "#;
        let result = parse_solidity(source, Path::new("Counter.sol"));
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(!parsed.tree.0.is_empty());
    }
}
