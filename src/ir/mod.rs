use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub type BasicBlockId = u32;
pub type FunctionId = u32;
pub type U256 = [u8; 32]; // Simplification for no-std or missing deps

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub length: usize,
    pub source_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub version: u32,
    pub var_type: TypeDescription,
    pub is_state_variable: bool,
    pub storage_slot: Option<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeDescription {
    Elementary(ElementaryType),
    Array { base: Box<TypeDescription>, length: Option<u64> },
    Mapping { key: Box<TypeDescription>, value: Box<TypeDescription> },
    Struct { name: String, members: Vec<(String, TypeDescription)> },
    Contract(String),
    Enum { name: String, members: Vec<String> },
    Function { params: Vec<TypeDescription>, returns: Vec<TypeDescription> },
    UserDefinedValueType { name: String, underlying: Box<TypeDescription> },
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ElementaryType {
    Address, Bool, String, Bytes,
    Uint(u16), Int(u16), BytesFixed(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction {
    Assign { dest: Variable, src: Operand },
    Phi { dest: Variable, sources: Vec<(BasicBlockId, Variable)> },
    BinaryOp { dest: Variable, op: BinaryOperator, left: Operand, right: Operand, checked: bool },
    UnaryOp { dest: Variable, op: UnaryOperator, operand: Operand },
    TypeConversion { dest: Variable, src: Operand, target_type: TypeDescription },
    InternalCall { dest: Option<Variable>, function: FunctionId, args: Vec<Operand> },
    ExternalCall { dest: Option<Variable>, target: Operand, function_selector: [u8; 4], args: Vec<Operand>, value: Option<Operand>, gas: Option<Operand> },
    DelegateCall { dest: Option<Variable>, target: Operand, function_selector: [u8; 4], args: Vec<Operand> },
    StaticCall { dest: Option<Variable>, target: Operand, function_selector: [u8; 4], args: Vec<Operand> },
    LowLevelCall { dest: Option<Variable>, target: Operand, data: Operand, value: Option<Operand> },
    StorageRead { dest: Variable, slot: Operand },
    StorageWrite { slot: Operand, value: Operand },
    TransientRead { dest: Variable, slot: Operand },
    TransientWrite { slot: Operand, value: Operand },
    MemoryRead { dest: Variable, offset: Operand },
    MemoryWrite { offset: Operand, value: Operand },
    Transfer { to: Operand, amount: Operand },
    Return { values: Vec<Operand> },
    Revert { data: Option<Operand> },
    Condition { variable: Operand, true_block: BasicBlockId, false_block: BasicBlockId },
    Jump { target: BasicBlockId },
    EmitEvent { event_name: String, args: Vec<Operand>, indexed: Vec<bool> },
    SelfDestruct { to: Operand },
    Balance { dest: Variable, address: Operand },
    CodeSize { dest: Variable, address: Operand },
    Require { condition: Operand, message: Option<Operand> },
    Assert { condition: Operand },
    InlineAssembly { code: String, reads: Vec<Variable>, writes: Vec<Variable>, memory_safe: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operand {
    Variable(Variable),
    Constant(Constant),
    MsgSender,
    MsgValue,
    MsgData,
    BlockTimestamp,
    BlockNumber,
    TxOrigin,
    ThisAddress,
    GasLeft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constant {
    Uint(u128, u16),
    Int(i128, u16),
    Bool(bool),
    Address([u8; 20]),
    Bytes(Vec<u8>),
    String(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinaryOperator {
    Add, Sub, Mul, Div, Mod, Exp,
    And, Or, Xor, Shl, Shr, Sar,
    Eq, Neq, Lt, Gt, Lte, Gte,
    LogicalAnd, LogicalOr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnaryOperator {
    Not, Neg, BitwiseNot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BasicBlockId,
    pub instructions: Vec<Instruction>,
    pub predecessors: Vec<BasicBlockId>,
    pub successors: Vec<BasicBlockId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Visibility {
    Public, External, Internal, Private,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Mutability {
    Pure, View, NonPayable, Payable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    pub id: FunctionId,
    pub name: String,
    pub contract_name: String,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub modifiers: Vec<String>,
    pub parameters: Vec<Variable>,
    pub return_variables: Vec<Variable>,
    pub basic_blocks: Vec<BasicBlock>,
    pub entry_block: BasicBlockId,
    pub is_constructor: bool,
    pub is_fallback: bool,
    pub is_receive: bool,
    pub source_location: SourceLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVariable {
    pub var: Variable,
    pub visibility: Visibility,
    pub is_constant: bool,
    pub is_immutable: bool,
    pub source_location: SourceLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrContract {
    pub name: String,
    pub functions: Vec<IrFunction>,
    pub state_variables: Vec<StateVariable>,
    pub inheritance_chain: Vec<String>,
    pub is_abstract: bool,
    pub is_interface: bool,
    pub is_library: bool,
    pub source_location: SourceLocation,
}

// Ensure you have semver crate added in your Cargo.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationUnit {
    pub contracts: Vec<IrContract>,
    pub source_files: Vec<PathBuf>,
    pub compiler_version: semver::Version,
}
