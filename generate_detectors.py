import os

base_dir = r"c:\Users\ashut\OneDrive\Documents\smartcontract-analyzer\src\detectors"
os.makedirs(base_dir, exist_ok=True)

mod_rs = '''use crate::context::WorkspaceContext;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence in the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// A single security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub detector_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: PathBuf,
    pub line: usize,
    pub contract_name: String,
    pub function_name: String,
    pub snippet: String,
    pub remediation: String,
    pub cwe: Option<String>,
    pub swc: Option<String>,
}

/// The detector trait. Each security check implements this.
pub trait Detector: Send + Sync {
    fn id(&self) -> &str;
    fn title(&self) -> &str;
    fn severity(&self) -> Severity;
    fn confidence(&self) -> Confidence;
    fn description(&self) -> &str;
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding>;
}

/// Registry holding all detectors.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self { Self { detectors: Vec::new() } }
    pub fn register(&mut self, d: Box<dyn Detector>) { self.detectors.push(d); }
    pub fn register_defaults(&mut self) {
        self.register(Box::new(reentrancy::ReentrancyDetector));
        self.register(Box::new(unchecked_call::UncheckedCallDetector));
        self.register(Box::new(unchecked_transfer::UncheckedTransferDetector));
        self.register(Box::new(tx_origin::TxOriginDetector));
        self.register(Box::new(unsafe_selfdestruct::UnsafeSelfdestructDetector));
        self.register(Box::new(arbitrary_delegatecall::ArbitraryDelegatecallDetector));
        self.register(Box::new(arbitrary_transferfrom::ArbitraryTransferfromDetector));
        self.register(Box::new(uninitialized_storage::UninitializedStorageDetector));
        self.register(Box::new(state_shadowing::StateShadowingDetector));
        self.register(Box::new(msg_value_loop::MsgValueLoopDetector));

        self.register(Box::new(calls_in_loop::CallsInLoopDetector));
        self.register(Box::new(division_before_multiply::DivisionBeforeMultiplyDetector));
        self.register(Box::new(missing_zero_check::MissingZeroCheckDetector));
        self.register(Box::new(locked_ether::LockedEtherDetector));
        self.register(Box::new(block_randomness::BlockRandomnessDetector));
        self.register(Box::new(strict_balance::StrictBalanceDetector));
        self.register(Box::new(floating_pragma::FloatingPragmaDetector));
        self.register(Box::new(unsafe_downcast::UnsafeDowncastDetector));
        self.register(Box::new(missing_gap::MissingGapDetector));
        self.register(Box::new(default_visibility::DefaultVisibilityDetector));

        self.register(Box::new(unused_return::UnusedReturnDetector));
        self.register(Box::new(abi_encode_packed::AbiEncodePackedDetector));
        self.register(Box::new(struct_mapping_delete::StructMappingDeleteDetector));
        self.register(Box::new(empty_payable::EmptyPayableDetector));
        self.register(Box::new(unicode_direction::UnicodeDirectionDetector));
        self.register(Box::new(unary_plus::UnaryPlusDetector));
        self.register(Box::new(assembly_return::AssemblyReturnDetector));
        self.register(Box::new(swapped_shift::SwappedShiftDetector));
        self.register(Box::new(multiple_constructors::MultipleConstructorsDetector));
        self.register(Box::new(enum_cast::EnumCastDetector));
    }
    pub fn run_all(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        self.detectors.iter().flat_map(|d| d.detect(ctx)).collect()
    }
    pub fn list(&self) -> Vec<(&str, &str, Severity)> {
        self.detectors.iter().map(|d| (d.id(), d.title(), d.severity())).collect()
    }
}

pub mod reentrancy;
pub mod unchecked_call;
pub mod unchecked_transfer;
pub mod tx_origin;
pub mod unsafe_selfdestruct;
pub mod arbitrary_delegatecall;
pub mod arbitrary_transferfrom;
pub mod uninitialized_storage;
pub mod state_shadowing;
pub mod msg_value_loop;

pub mod calls_in_loop;
pub mod division_before_multiply;
pub mod missing_zero_check;
pub mod locked_ether;
pub mod block_randomness;
pub mod strict_balance;
pub mod floating_pragma;
pub mod unsafe_downcast;
pub mod missing_gap;
pub mod default_visibility;

pub mod unused_return;
pub mod abi_encode_packed;
pub mod struct_mapping_delete;
pub mod empty_payable;
pub mod unicode_direction;
pub mod unary_plus;
pub mod assembly_return;
pub mod swapped_shift;
pub mod multiple_constructors;
pub mod enum_cast;
'''

with open(os.path.join(base_dir, 'mod.rs'), 'w', encoding='utf-8') as f:
    f.write(mod_rs)

detectors = {
    # Tier 1
    "reentrancy": {
        "struct": "ReentrancyDetector",
        "id": "REENTRANCY",
        "title": "Reentrancy",
        "sev": "High",
        "conf": "High",
        "desc": "State write after external call without nonReentrant modifier.",
        "logic": '''
        for func in &ctx.functions {
            if !func.external_calls.is_empty() && !func.state_writes.is_empty() {
                let has_modifier = func.modifiers.iter().any(|m| m.contains("nonReentrant") || m.contains("noReentrant"));
                if !has_modifier {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Use nonReentrant modifier or CEI pattern".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "unchecked_call": {
        "struct": "UncheckedCallDetector",
        "id": "UNCHECKED_CALL",
        "title": "Unchecked Call",
        "sev": "High",
        "conf": "High",
        "desc": "Function body contains .call but the return value is not checked.",
        "logic": '''
        for func in &ctx.functions {
            if (func.body_source.contains(".call{") || func.body_source.contains(".call(")) && 
               !(func.body_source.contains("require(success") || func.body_source.contains("if (!success") || func.body_source.contains("if(!success")) {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Check return value".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "unchecked_transfer": {
        "struct": "UncheckedTransferDetector",
        "id": "UNCHECKED_TRANSFER",
        "title": "Unchecked Transfer",
        "sev": "High",
        "conf": "High",
        "desc": "Calls to .transfer( or .transferFrom( without SafeERC20.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains(".transfer(") || func.body_source.contains(".transferFrom(") {
                let contract = &ctx.contracts[func.contract_idx];
                // basic heuristic for SafeERC20 check
                let source = &ctx.sources[contract.source_idx].source;
                if !source.contains("SafeERC20") && !func.body_source.contains("safeTransfer") {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: contract.name.clone(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Use SafeERC20".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "tx_origin": {
        "struct": "TxOriginDetector",
        "id": "TX_ORIGIN",
        "title": "Tx Origin Authentication",
        "sev": "High",
        "conf": "High",
        "desc": "tx.origin used for authentication.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains("tx.origin") && (func.body_source.contains("require(") || func.body_source.contains("if (")) {
                if !func.body_source.contains("msg.sender") { // suppress if combined with msg.sender
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Use msg.sender instead".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "unsafe_selfdestruct": {
        "struct": "UnsafeSelfdestructDetector",
        "id": "UNSAFE_SELFDESTRUCT",
        "title": "Unsafe Selfdestruct",
        "sev": "High",
        "conf": "High",
        "desc": "selfdestruct without proper access control.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains("selfdestruct(") {
                let has_modifier = func.modifiers.iter().any(|m| m.contains("onlyOwner") || m.contains("onlyRole") || m.contains("auth"));
                let has_require = func.body_source.contains("require(msg.sender ==");
                if !has_modifier && !has_require {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Protect selfdestruct with access control".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "arbitrary_delegatecall": {
        "struct": "ArbitraryDelegatecallDetector",
        "id": "ARBITRARY_DELEGATECALL",
        "title": "Arbitrary Delegatecall",
        "sev": "High",
        "conf": "Medium",
        "desc": "delegatecall with user-controlled target.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains(".delegatecall(") {
                // Heuristic: check if any param name is used near .delegatecall
                let suspicious = func.params.iter().any(|p| func.body_source.contains(&format!("{}.delegatecall", p.name)));
                if suspicious {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Do not allow user-controlled delegatecall target".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "arbitrary_transferfrom": {
        "struct": "ArbitraryTransferfromDetector",
        "id": "ARBITRARY_TRANSFERFROM",
        "title": "Arbitrary TransferFrom",
        "sev": "High",
        "conf": "Medium",
        "desc": "transferFrom where from parameter is user-supplied.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains(".transferFrom(") {
                let suspicious = func.params.iter().any(|p| {
                    func.body_source.contains(&format!(".transferFrom({},", p.name)) || 
                    func.body_source.contains(&format!(".transferFrom( {},", p.name))
                });
                if suspicious {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Ensure 'from' is msg.sender".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "uninitialized_storage": {
        "struct": "UninitializedStorageDetector",
        "id": "UNINITIALIZED_STORAGE",
        "title": "Uninitialized Storage",
        "sev": "High",
        "conf": "Low",
        "desc": "Local variable declared as storage but not initialized.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains(" storage ") && !func.body_source.contains(" = ") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Initialize storage pointers".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "state_shadowing": {
        "struct": "StateShadowingDetector",
        "id": "STATE_SHADOWING",
        "title": "State Variable Shadowing",
        "sev": "High",
        "conf": "High",
        "desc": "State variable shadows base contract variable.",
        "logic": '''
        for contract in &ctx.contracts {
            let mut base_vars = std::collections::HashSet::new();
            for base_name in &contract.bases {
                if let Some(base_contract) = ctx.contracts.iter().find(|c| c.name == *base_name) {
                    for &var_idx in &base_contract.state_variables {
                        if let Some(v) = ctx.state_variables.get(var_idx) {
                            base_vars.insert(v.name.clone());
                        }
                    }
                }
            }
            for &var_idx in &contract.state_variables {
                if let Some(v) = ctx.state_variables.get(var_idx) {
                    if base_vars.contains(&v.name) {
                        findings.push(Finding {
                            detector_id: self.id().to_string(),
                            title: self.title().to_string(),
                            description: self.description().to_string(),
                            severity: self.severity(),
                            confidence: self.confidence(),
                            file: v.loc.file.clone(),
                            line: v.loc.start,
                            contract_name: contract.name.clone(),
                            function_name: String::new(),
                            snippet: v.name.clone(),
                            remediation: "Rename shadowed variable".to_string(),
                            cwe: None,
                            swc: None,
                        });
                    }
                }
            }
        }
        '''
    },
    "msg_value_loop": {
        "struct": "MsgValueLoopDetector",
        "id": "MSG_VALUE_LOOP",
        "title": "Msg.value in Loop",
        "sev": "High",
        "conf": "Medium",
        "desc": "msg.value used inside a loop.",
        "logic": '''
        for func in &ctx.functions {
            if func.has_loops && func.body_source.contains("msg.value") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Avoid using msg.value inside loops".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    # Tier 2
    "calls_in_loop": {
        "struct": "CallsInLoopDetector",
        "id": "CALLS_IN_LOOP",
        "title": "Calls in Loop",
        "sev": "Medium",
        "conf": "High",
        "desc": "External calls inside a loop.",
        "logic": '''
        for func in &ctx.functions {
            if func.has_loops && !func.external_calls.is_empty() {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Avoid external calls in loops to prevent DoS".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "division_before_multiply": {
        "struct": "DivisionBeforeMultiplyDetector",
        "id": "DIVISION_BEFORE_MULTIPLY",
        "title": "Division Before Multiply",
        "sev": "Medium",
        "conf": "Medium",
        "desc": "Division operation appears before multiplication.",
        "logic": '''
        for func in &ctx.functions {
            let parts: Vec<&str> = func.body_source.split(';').collect();
            for part in parts {
                if let Some(div_pos) = part.find('/') {
                    if let Some(mul_pos) = part.find('*') {
                        if div_pos < mul_pos {
                            findings.push(Finding {
                                detector_id: self.id().to_string(),
                                title: self.title().to_string(),
                                description: self.description().to_string(),
                                severity: self.severity(),
                                confidence: self.confidence(),
                                file: func.loc.file.clone(),
                                line: func.loc.start,
                                contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                                function_name: func.name.clone(),
                                snippet: part.to_string(),
                                remediation: "Multiply before dividing to avoid precision loss".to_string(),
                                cwe: None,
                                swc: None,
                            });
                        }
                    }
                }
            }
        }
        '''
    },
    "missing_zero_check": {
        "struct": "MissingZeroCheckDetector",
        "id": "MISSING_ZERO_CHECK",
        "title": "Missing Zero Check",
        "sev": "Medium",
        "conf": "Medium",
        "desc": "Missing address(0) check in initializer.",
        "logic": '''
        for func in &ctx.functions {
            if func.is_constructor || func.name == "initialize" {
                let has_address_param = func.params.iter().any(|p| p.type_name.contains("address"));
                if has_address_param {
                    let has_check = func.body_source.contains("!= address(0)") || func.body_source.contains("!= address(0x0)");
                    if !has_check {
                        findings.push(Finding {
                            detector_id: self.id().to_string(),
                            title: self.title().to_string(),
                            description: self.description().to_string(),
                            severity: self.severity(),
                            confidence: self.confidence(),
                            file: func.loc.file.clone(),
                            line: func.loc.start,
                            contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                            function_name: func.name.clone(),
                            snippet: func.body_source.clone(),
                            remediation: "Add require checks for address(0)".to_string(),
                            cwe: None,
                            swc: None,
                        });
                    }
                }
            }
        }
        '''
    },
    "locked_ether": {
        "struct": "LockedEtherDetector",
        "id": "LOCKED_ETHER",
        "title": "Locked Ether",
        "sev": "Medium",
        "conf": "High",
        "desc": "Contract accepts ether but cannot send it.",
        "logic": '''
        for contract in &ctx.contracts {
            let mut has_payable = false;
            let mut can_send = false;
            for &f_idx in &contract.functions {
                let f = &ctx.functions[f_idx];
                if f.is_receive || f.is_fallback || f.mutability == crate::context::Mutability::Payable {
                    has_payable = true;
                }
                if f.body_source.contains(".transfer(") || f.body_source.contains(".send(") || f.body_source.contains(".call{value:") {
                    can_send = true;
                }
            }
            if has_payable && !can_send {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: contract.loc.file.clone(),
                    line: contract.loc.start,
                    contract_name: contract.name.clone(),
                    function_name: String::new(),
                    snippet: String::new(),
                    remediation: "Implement a way to withdraw ether".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "block_randomness": {
        "struct": "BlockRandomnessDetector",
        "id": "BLOCK_RANDOMNESS",
        "title": "Block Randomness",
        "sev": "Medium",
        "conf": "High",
        "desc": "Using block variables for randomness.",
        "logic": '''
        for func in &ctx.functions {
            let triggers = ["block.timestamp", "blockhash(", "block.difficulty", "block.prevrandao"];
            for t in triggers {
                if func.body_source.contains(t) {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Use secure randomness (e.g. Chainlink VRF)".to_string(),
                        cwe: None,
                        swc: None,
                    });
                    break;
                }
            }
        }
        '''
    },
    "strict_balance": {
        "struct": "StrictBalanceDetector",
        "id": "STRICT_BALANCE",
        "title": "Strict Balance Equality",
        "sev": "Medium",
        "conf": "High",
        "desc": "Checking address(this).balance exactly.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains("address(this).balance ==") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Use >= instead of ==".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "floating_pragma": {
        "struct": "FloatingPragmaDetector",
        "id": "FLOATING_PRAGMA",
        "title": "Floating Pragma",
        "sev": "Medium",
        "conf": "High",
        "desc": "Source uses a floating pragma.",
        "logic": '''
        for src in &ctx.sources {
            if let Some(idx) = src.source.find("pragma solidity") {
                let end = src.source[idx..].find(';').unwrap_or(src.source.len() - idx);
                let pragma_stmt = &src.source[idx..idx+end];
                if pragma_stmt.contains('^') || pragma_stmt.contains(">=") {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: src.path.clone(),
                        line: 0,
                        contract_name: String::new(),
                        function_name: String::new(),
                        snippet: pragma_stmt.to_string(),
                        remediation: "Pin the pragma version".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "unsafe_downcast": {
        "struct": "UnsafeDowncastDetector",
        "id": "UNSAFE_DOWNCAST",
        "title": "Unsafe Downcast",
        "sev": "Medium",
        "conf": "Medium",
        "desc": "Unsafe integer downcast.",
        "logic": '''
        for func in &ctx.functions {
            let casts = ["uint128(", "uint64(", "uint32(", "uint16(", "uint8("];
            for c in casts {
                if func.body_source.contains(c) && !func.body_source.contains("SafeCast") {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Use SafeCast library".to_string(),
                        cwe: None,
                        swc: None,
                    });
                    break;
                }
            }
        }
        '''
    },
    "missing_gap": {
        "struct": "MissingGapDetector",
        "id": "MISSING_GAP",
        "title": "Missing Gap in Upgradeable",
        "sev": "Medium",
        "conf": "Medium",
        "desc": "Upgradeable base without __gap variable.",
        "logic": '''
        for contract in &ctx.contracts {
            let is_upgradeable = contract.name.contains("Upgradeable") || contract.bases.iter().any(|b| b.contains("Upgradeable"));
            if is_upgradeable {
                let has_gap = contract.state_variables.iter().any(|&v_idx| {
                    if let Some(v) = ctx.state_variables.get(v_idx) {
                        v.name == "__gap"
                    } else { false }
                });
                if !has_gap {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: contract.loc.file.clone(),
                        line: contract.loc.start,
                        contract_name: contract.name.clone(),
                        function_name: String::new(),
                        snippet: String::new(),
                        remediation: "Add uint256[50] private __gap;".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "default_visibility": {
        "struct": "DefaultVisibilityDetector",
        "id": "DEFAULT_VISIBILITY",
        "title": "Default Visibility",
        "sev": "Medium",
        "conf": "High",
        "desc": "Function missing explicit visibility.",
        "logic": '''
        for func in &ctx.functions {
            if func.visibility == crate::context::Visibility::Default && !func.is_constructor {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.name.clone(),
                    remediation: "Explicitly specify visibility".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    # Tier 3
    "unused_return": {
        "struct": "UnusedReturnDetector",
        "id": "UNUSED_RETURN",
        "title": "Unused Return Value",
        "sev": "Low",
        "conf": "Low",
        "desc": "Return value of a function is not checked.",
        "logic": '''
        for func in &ctx.functions {
            let lines: Vec<&str> = func.body_source.lines().collect();
            for line in lines {
                if line.contains('(') && line.contains(");") && !line.contains('=') && !line.contains("require") && !line.contains("if") {
                    // heuristic for a standalone call
                    if line.trim().starts_with("require") || line.trim().starts_with("assert") || line.trim().starts_with("emit ") || line.trim().starts_with("revert") {
                        continue;
                    }
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: line.trim().to_string(),
                        remediation: "Capture and handle the return value".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "abi_encode_packed": {
        "struct": "AbiEncodePackedDetector",
        "id": "ABI_ENCODE_PACKED",
        "title": "abi.encodePacked with Dynamics",
        "sev": "Low",
        "conf": "Low",
        "desc": "abi.encodePacked can lead to hash collisions.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains("abi.encodePacked(") && func.body_source.contains(",") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: "abi.encodePacked".to_string(),
                    remediation: "Use abi.encode() instead if packing multiple dynamic parameters".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "struct_mapping_delete": {
        "struct": "StructMappingDeleteDetector",
        "id": "STRUCT_MAPPING_DELETE",
        "title": "Struct Mapping Delete",
        "sev": "Low",
        "conf": "Medium",
        "desc": "Deleting a struct containing a mapping leaves the mapping intact.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains("delete ") {
                // Since full type inference isn't available, report all deletes as warning.
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Ensure the struct does not contain mappings".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "empty_payable": {
        "struct": "EmptyPayableDetector",
        "id": "EMPTY_PAYABLE",
        "title": "Empty Payable Function",
        "sev": "Low",
        "conf": "High",
        "desc": "Receive or fallback is empty.",
        "logic": '''
        for func in &ctx.functions {
            if (func.is_receive || func.is_fallback) && func.mutability == crate::context::Mutability::Payable {
                let trimmed = func.body_source.replace(" ", "").replace("\\n", "");
                if trimmed == "{}" || trimmed.is_empty() {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: func.loc.file.clone(),
                        line: func.loc.start,
                        contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                        function_name: func.name.clone(),
                        snippet: func.body_source.clone(),
                        remediation: "Ensure intention of empty payable".to_string(),
                        cwe: None,
                        swc: None,
                    });
                }
            }
        }
        '''
    },
    "unicode_direction": {
        "struct": "UnicodeDirectionDetector",
        "id": "UNICODE_DIRECTION",
        "title": "Unicode Direction Override",
        "sev": "Low",
        "conf": "High",
        "desc": "Contains unicode direction override chars.",
        "logic": '''
        for src in &ctx.sources {
            let malicious_chars = ["\\u202E", "\\u202D", "\\u202C"];
            for mc in malicious_chars {
                if src.source.contains(mc) {
                    findings.push(Finding {
                        detector_id: self.id().to_string(),
                        title: self.title().to_string(),
                        description: self.description().to_string(),
                        severity: self.severity(),
                        confidence: self.confidence(),
                        file: src.path.clone(),
                        line: 0,
                        contract_name: String::new(),
                        function_name: String::new(),
                        snippet: String::new(),
                        remediation: "Remove bidirectional unicode characters".to_string(),
                        cwe: None,
                        swc: None,
                    });
                    break;
                }
            }
        }
        '''
    },
    "unary_plus": {
        "struct": "UnaryPlusDetector",
        "id": "UNARY_PLUS",
        "title": "Unary Plus Typo",
        "sev": "Low",
        "conf": "High",
        "desc": "= + typo for +=.",
        "logic": '''
        for func in &ctx.functions {
            if func.body_source.contains("=+") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: "=+".to_string(),
                    remediation: "Change to +=".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "assembly_return": {
        "struct": "AssemblyReturnDetector",
        "id": "ASSEMBLY_RETURN",
        "title": "Assembly Return",
        "sev": "Low",
        "conf": "High",
        "desc": "Return inside assembly instead of leave.",
        "logic": '''
        for func in &ctx.functions {
            if func.has_assembly && func.body_source.contains("return(") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: "return(".to_string(),
                    remediation: "Use 'leave' or 'return' properly".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "swapped_shift": {
        "struct": "SwappedShiftDetector",
        "id": "SWAPPED_SHIFT",
        "title": "Swapped Shift Ops",
        "sev": "Low",
        "conf": "Low",
        "desc": "shl or shr usage in assembly.",
        "logic": '''
        for func in &ctx.functions {
            if func.has_assembly && (func.body_source.contains("shl(") || func.body_source.contains("shr(")) {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Ensure shift parameter order is correct".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "multiple_constructors": {
        "struct": "MultipleConstructorsDetector",
        "id": "MULTIPLE_CONSTRUCTORS",
        "title": "Multiple Constructors",
        "sev": "Low",
        "conf": "High",
        "desc": "Multiple constructors in a contract.",
        "logic": '''
        for contract in &ctx.contracts {
            let mut cons_count = 0;
            for &f_idx in &contract.functions {
                if ctx.functions[f_idx].is_constructor {
                    cons_count += 1;
                }
            }
            if cons_count > 1 {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: contract.loc.file.clone(),
                    line: contract.loc.start,
                    contract_name: contract.name.clone(),
                    function_name: String::new(),
                    snippet: String::new(),
                    remediation: "Remove extra constructors".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
    "enum_cast": {
        "struct": "EnumCastDetector",
        "id": "ENUM_CAST",
        "title": "Unsafe Enum Cast",
        "sev": "Low",
        "conf": "Low",
        "desc": "Explicit enum type cast.",
        "logic": '''
        for func in &ctx.functions {
            // Very simple heuristic for explicit cast
            if func.body_source.contains(")(") {
                findings.push(Finding {
                    detector_id: self.id().to_string(),
                    title: self.title().to_string(),
                    description: self.description().to_string(),
                    severity: self.severity(),
                    confidence: self.confidence(),
                    file: func.loc.file.clone(),
                    line: func.loc.start,
                    contract_name: ctx.contracts.get(func.contract_idx).map(|c| c.name.clone()).unwrap_or_default(),
                    function_name: func.name.clone(),
                    snippet: func.body_source.clone(),
                    remediation: "Validate bounds when casting to enum".to_string(),
                    cwe: None,
                    swc: None,
                });
            }
        }
        '''
    },
}

for name, meta in detectors.items():
    code = f'''use crate::context::WorkspaceContext;
use crate::detectors::{{Detector, Finding, Severity, Confidence}};

pub struct {meta["struct"]};

impl Detector for {meta["struct"]} {{
    fn id(&self) -> &str {{ "{meta["id"]}" }}
    fn title(&self) -> &str {{ "{meta["title"]}" }}
    fn severity(&self) -> Severity {{ Severity::{meta["sev"]} }}
    fn confidence(&self) -> Confidence {{ Confidence::{meta["conf"]} }}
    fn description(&self) -> &str {{ "{meta["desc"]}" }}

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Finding> {{
        let mut findings = Vec::new();
        {meta["logic"]}
        findings
    }}
}}
'''
    with open(os.path.join(base_dir, f"{name}.rs"), 'w', encoding='utf-8') as f:
        f.write(code)

print("Done generating detectors.")
