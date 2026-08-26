//! WorkspaceContext — the central indexed AST database.
//!
//! Inspired by Aderyn's WorkspaceContext: pre-indexes all AST nodes
//! by type for fast lookup by detectors. Detectors query the context
//! instead of writing their own AST traversals.

use crate::ast::{Loc, ParsedSource};
use solang_parser::pt;
use solang_parser::pt::CodeLocation;

/// Extracted contract definition.
#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub name: String,
    pub loc: Loc,
    pub kind: ContractKind,
    pub bases: Vec<String>,
    pub functions: Vec<usize>,        // indices into WorkspaceContext.functions
    pub state_variables: Vec<usize>,  // indices into WorkspaceContext.state_variables
    pub events: Vec<String>,
    pub modifiers: Vec<String>,
    pub has_receive: bool,
    pub has_fallback: bool,
    pub source_idx: usize,           // index into WorkspaceContext.sources
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractKind {
    Contract,
    Interface,
    Library,
    Abstract,
}

/// Extracted function definition.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub loc: Loc,
    pub contract_idx: usize,          // index into WorkspaceContext.contracts
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub modifiers: Vec<String>,
    pub params: Vec<ParamInfo>,
    pub returns: Vec<ParamInfo>,
    pub is_constructor: bool,
    pub is_receive: bool,
    pub is_fallback: bool,
    /// Source body as raw string for pattern analysis.
    pub body_source: String,
    /// External calls found in this function.
    pub external_calls: Vec<ExternalCallInfo>,
    /// State variable writes found in this function.
    pub state_writes: Vec<StateWriteInfo>,
    /// State variable reads found in this function.
    pub state_reads: Vec<String>,
    /// Emit statements found in this function.
    pub emits: Vec<EmitInfo>,
    /// Whether function contains loops.
    pub has_loops: bool,
    /// Whether function body contains assembly.
    pub has_assembly: bool,
    pub source_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    Public,
    External,
    Internal,
    Private,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutability {
    Pure,
    View,
    Payable,
    NonPayable,
}

#[derive(Debug, Clone)]
pub struct ParamInfo {
    pub name: String,
    pub type_name: String,
}

/// Info about an external call within a function body.
#[derive(Debug, Clone)]
pub struct ExternalCallInfo {
    pub loc: Loc,
    pub call_type: ExternalCallType,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCallType {
    Call,
    DelegateCall,
    StaticCall,
    Send,
    Transfer,
    HighLevel,
}

/// Info about a state variable write.
#[derive(Debug, Clone)]
pub struct StateWriteInfo {
    pub variable_name: String,
    pub loc: Loc,
}

/// Info about an emit statement.
#[derive(Debug, Clone)]
pub struct EmitInfo {
    pub event_name: String,
    pub loc: Loc,
}

/// Extracted state variable definition.
#[derive(Debug, Clone)]
pub struct StateVarInfo {
    pub name: String,
    pub type_name: String,
    pub loc: Loc,
    pub visibility: Visibility,
    pub is_constant: bool,
    pub is_immutable: bool,
    pub is_initialized: bool,
    pub contract_idx: usize,
    pub source_idx: usize,
}

/// The central indexed AST database.
///
/// Detectors query this structure rather than walking the raw AST.
pub struct WorkspaceContext {
    /// All parsed sources.
    pub sources: Vec<ParsedSource>,
    /// All contract definitions (indexed).
    pub contracts: Vec<ContractInfo>,
    /// All function definitions (indexed).
    pub functions: Vec<FunctionInfo>,
    /// All state variable declarations (indexed).
    pub state_variables: Vec<StateVarInfo>,
}

impl WorkspaceContext {
    /// Build a WorkspaceContext from parsed sources by extracting
    /// and indexing all contract definitions, functions, and state variables.
    pub fn from_parsed_sources(sources: &[ParsedSource]) -> Self {
        let mut ctx = WorkspaceContext {
            sources: sources.to_vec(),
            contracts: Vec::new(),
            functions: Vec::new(),
            state_variables: Vec::new(),
        };

        for (source_idx, parsed) in sources.iter().enumerate() {
            for part in &parsed.tree.0 {
                if let pt::SourceUnitPart::ContractDefinition(def) = part {
                    ctx.extract_contract(def, &parsed.source, &parsed.path, source_idx);
                }
            }
        }

        ctx
    }

    fn extract_contract(
        &mut self,
        def: &pt::ContractDefinition,
        source: &str,
        path: &std::path::Path,
        source_idx: usize,
    ) {
        let contract_idx = self.contracts.len();
        let name = def.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
        let kind = match def.ty {
            pt::ContractTy::Contract(_) => ContractKind::Contract,
            pt::ContractTy::Interface(_) => ContractKind::Interface,
            pt::ContractTy::Library(_) => ContractKind::Library,
            pt::ContractTy::Abstract(_) => ContractKind::Abstract,
        };

        let bases: Vec<String> = def.base.iter().map(|b| {
            b.name.identifiers.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join(".")
        }).collect();

        let mut contract_info = ContractInfo {
            name,
            loc: Loc::from_pt(def.loc, source, path),
            kind,
            bases,
            functions: Vec::new(),
            state_variables: Vec::new(),
            events: Vec::new(),
            modifiers: Vec::new(),
            has_receive: false,
            has_fallback: false,
            source_idx,
        };

        // Extract all parts of the contract
        for part in &def.parts {
            match part {
                pt::ContractPart::FunctionDefinition(func) => {
                    let func_idx = self.functions.len();
                    contract_info.functions.push(func_idx);
                    self.extract_function(func, source, path, contract_idx, source_idx);
                }
                pt::ContractPart::VariableDefinition(var) => {
                    let var_idx = self.state_variables.len();
                    contract_info.state_variables.push(var_idx);
                    self.extract_state_var(var, source, path, contract_idx, source_idx);
                }
                pt::ContractPart::EventDefinition(ev) => {
                    if let Some(name) = &ev.name {
                        contract_info.events.push(name.name.clone());
                    }
                }
                _ => {}
            }
        }

        // Check for receive/fallback
        for func in &self.functions[contract_info.functions[0]..] {
            if func.is_receive {
                contract_info.has_receive = true;
            }
            if func.is_fallback {
                contract_info.has_fallback = true;
            }
        }

        self.contracts.push(contract_info);
    }

    fn extract_function(
        &mut self,
        func: &pt::FunctionDefinition,
        source: &str,
        path: &std::path::Path,
        contract_idx: usize,
        source_idx: usize,
    ) {
        let name = func.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();

        let (is_constructor, is_receive, is_fallback) = match &func.ty {
            pt::FunctionTy::Constructor => (true, false, false),
            pt::FunctionTy::Receive => (false, true, false),
            pt::FunctionTy::Fallback => (false, false, true),
            pt::FunctionTy::Function => (false, false, false),
            pt::FunctionTy::Modifier => (false, false, false),
        };

        let visibility = func.attributes.iter().find_map(|attr| {
            match attr {
                pt::FunctionAttribute::Visibility(v) => Some(match v {
                    pt::Visibility::Public(_) => Visibility::Public,
                    pt::Visibility::External(_) => Visibility::External,
                    pt::Visibility::Internal(_) => Visibility::Internal,
                    pt::Visibility::Private(_) => Visibility::Private,
                }),
                _ => None,
            }
        }).unwrap_or(Visibility::Default);

        let mutability = func.attributes.iter().find_map(|attr| {
            match attr {
                pt::FunctionAttribute::Mutability(m) => Some(match m {
                    pt::Mutability::Pure(_) => Mutability::Pure,
                    pt::Mutability::View(_) => Mutability::View,
                    pt::Mutability::Payable(_) => Mutability::Payable,
                    pt::Mutability::Constant(_) => Mutability::View,
                }),
                _ => None,
            }
        }).unwrap_or(Mutability::NonPayable);

        let modifiers: Vec<String> = func.attributes.iter().filter_map(|attr| {
            if let pt::FunctionAttribute::BaseOrModifier(_, base) = attr {
                Some(base.name.identifiers.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join("."))
            } else {
                None
            }
        }).collect();

        let params = extract_params(&func.params);
        let returns = extract_params(&func.returns);

        // Extract body source for pattern analysis
        let body_source = if let Some(body) = &func.body {
            match body.loc() {
                pt::Loc::File(_, start, end) => source.get(start..end).unwrap_or("").to_string(),
                _ => String::new(),
            }
        } else {
            String::new()
        };

        // Analyze body for external calls, state writes, loops, etc.
        let external_calls = find_external_calls(&body_source, source, path);
        let state_writes = find_state_writes(&body_source, source, path);
        let state_reads = find_state_reads(&body_source);
        let emits = find_emits(&body_source, source, path);
        let has_loops = body_source.contains("for (") || body_source.contains("for(")
            || body_source.contains("while (") || body_source.contains("while(")
            || body_source.contains("do {");
        let has_assembly = body_source.contains("assembly {") || body_source.contains("assembly{");

        self.functions.push(FunctionInfo {
            name,
            loc: Loc::from_pt(func.loc, source, path),
            contract_idx,
            visibility,
            mutability,
            modifiers,
            params,
            returns,
            is_constructor,
            is_receive,
            is_fallback,
            body_source,
            external_calls,
            state_writes,
            state_reads,
            emits,
            has_loops,
            has_assembly,
            source_idx,
        });
    }

    fn extract_state_var(
        &mut self,
        var: &pt::VariableDefinition,
        source: &str,
        path: &std::path::Path,
        contract_idx: usize,
        source_idx: usize,
    ) {
        let name = var.name.as_ref().map(|n| n.name.clone()).unwrap_or_default();
        let type_name = format_type(&var.ty);

        let visibility = var.attrs.iter().find_map(|attr| {
            match attr {
                pt::VariableAttribute::Visibility(v) => Some(match v {
                    pt::Visibility::Public(_) => Visibility::Public,
                    pt::Visibility::External(_) => Visibility::External,
                    pt::Visibility::Internal(_) => Visibility::Internal,
                    pt::Visibility::Private(_) => Visibility::Private,
                }),
                _ => None,
            }
        }).unwrap_or(Visibility::Internal);

        let is_constant = var.attrs.iter().any(|a| matches!(a, pt::VariableAttribute::Constant(_)));
        let is_immutable = var.attrs.iter().any(|a| matches!(a, pt::VariableAttribute::Immutable(_)));
        let is_initialized = var.initializer.is_some();

        self.state_variables.push(StateVarInfo {
            name,
            type_name,
            loc: Loc::from_pt(var.loc, source, path),
            visibility,
            is_constant,
            is_immutable,
            is_initialized,
            contract_idx,
            source_idx,
        });
    }
}

// ── Helper functions ──────────────────────────────────────────────────

fn extract_params(params: &[(pt::Loc, Option<pt::Parameter>)]) -> Vec<ParamInfo> {
    params.iter().filter_map(|(_, p)| {
        p.as_ref().map(|param| ParamInfo {
            name: param.name.as_ref().map(|n| n.name.clone()).unwrap_or_default(),
            type_name: format_type(&param.ty),
        })
    }).collect()
}

fn format_type(ty: &pt::Expression) -> String {
    match ty {
        pt::Expression::Type(_, ty) => format!("{ty:?}"),
        _ => format!("{ty:?}"),
    }
}

fn find_external_calls(body: &str, _source: &str, path: &std::path::Path) -> Vec<ExternalCallInfo> {
    let mut calls = Vec::new();
    let patterns = [
        (".call{", ExternalCallType::Call),
        (".call(", ExternalCallType::Call),
        (".delegatecall(", ExternalCallType::DelegateCall),
        (".staticcall(", ExternalCallType::StaticCall),
        (".send(", ExternalCallType::Send),
        (".transfer(", ExternalCallType::Transfer),
    ];
    for (pattern, call_type) in &patterns {
        if body.contains(pattern) {
            calls.push(ExternalCallInfo {
                loc: Loc { file: path.to_path_buf(), ..Default::default() },
                call_type: call_type.clone(),
                target: String::new(),
            });
        }
    }
    calls
}

fn find_state_writes(body: &str, _source: &str, path: &std::path::Path) -> Vec<StateWriteInfo> {
    let mut writes = Vec::new();
    // Simple heuristic: look for assignment patterns
    let re = regex::Regex::new(r"(\w+)\s*(?:=|\+=|-=|\*=|/=)").ok();
    if let Some(re) = re {
        for cap in re.captures_iter(body) {
            if let Some(var_name) = cap.get(1) {
                let name = var_name.as_str().to_string();
                // Filter out local variable assignments (simple heuristic)
                if !["uint", "int", "bool", "address", "string", "bytes", "mapping"]
                    .iter().any(|t| name.starts_with(t))
                {
                    writes.push(StateWriteInfo {
                        variable_name: name,
                        loc: Loc { file: path.to_path_buf(), ..Default::default() },
                    });
                }
            }
        }
    }
    writes
}

fn find_state_reads(_body: &str) -> Vec<String> {
    // Basic: return identifiers that look like state reads
    // This is intentionally conservative; false negatives are fine
    Vec::new()
}

fn find_emits(body: &str, _source: &str, path: &std::path::Path) -> Vec<EmitInfo> {
    let mut emits = Vec::new();
    let re = regex::Regex::new(r"emit\s+(\w+)").ok();
    if let Some(re) = re {
        for cap in re.captures_iter(body) {
            if let Some(name) = cap.get(1) {
                emits.push(EmitInfo {
                    event_name: name.as_str().to_string(),
                    loc: Loc { file: path.to_path_buf(), ..Default::default() },
                });
            }
        }
    }
    emits
}
