use crate::context::WorkspaceContext;
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

        // New Detectors
        self.register(Box::new(oracle_staleness::OracleStalenessDetector));
        self.register(Box::new(deprecated_chainlink::DeprecatedChainlinkDetector));
        self.register(Box::new(single_oracle::SingleOracleDetector));
        self.register(Box::new(unprotected_initializer::UnprotectedInitializerDetector));
        self.register(Box::new(missing_disable_initializers::MissingDisableInitializersDetector));
        self.register(Box::new(uups_missing_upgrade_auth::UupsMissingUpgradeAuthDetector));
        self.register(Box::new(delegatecall_in_constructor::DelegatecallInConstructorDetector));
        self.register(Box::new(immutable_in_upgradeable::ImmutableInUpgradeableDetector));
        self.register(Box::new(erc20_approve_race::Erc20ApproveRaceDetector));
        self.register(Box::new(erc777_reentrancy::Erc777ReentrancyDetector));
        self.register(Box::new(missing_slippage::MissingSlippageDetector));
        self.register(Box::new(missing_deadline::MissingDeadlineDetector));
        self.register(Box::new(first_depositor::FirstDepositorDetector));
        self.register(Box::new(ecrecover_no_check::EcrecoverNoCheckDetector));
        self.register(Box::new(missing_nonce::MissingNonceDetector));
        self.register(Box::new(push0_compatibility::Push0CompatibilityDetector));
        self.register(Box::new(create2_address_reuse::Create2AddressReuseDetector));
        self.register(Box::new(boolean_constant_comparison::BooleanConstantComparisonDetector));
        self.register(Box::new(costly_loop_sload::CostlyLoopSloadDetector));
        self.register(Box::new(hardcoded_gas::HardcodedGasDetector));
    }
    pub fn run_all(&self, ctx: &WorkspaceContext) -> Vec<Finding> {
        self.detectors.iter().flat_map(|d| d.detect(ctx)).collect()
    }
    pub fn list(&self) -> Vec<(&str, &str, Severity, Confidence)> {
        self.detectors.iter().map(|d| (d.id(), d.title(), d.severity(), d.confidence())).collect()
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

pub mod oracle_staleness;
pub mod deprecated_chainlink;
pub mod single_oracle;
pub mod unprotected_initializer;
pub mod missing_disable_initializers;
pub mod uups_missing_upgrade_auth;
pub mod delegatecall_in_constructor;
pub mod immutable_in_upgradeable;
pub mod erc20_approve_race;
pub mod erc777_reentrancy;
pub mod missing_slippage;
pub mod missing_deadline;
pub mod first_depositor;
pub mod ecrecover_no_check;
pub mod missing_nonce;
pub mod push0_compatibility;
pub mod create2_address_reuse;
pub mod boolean_constant_comparison;
pub mod costly_loop_sload;
pub mod hardcoded_gas;
