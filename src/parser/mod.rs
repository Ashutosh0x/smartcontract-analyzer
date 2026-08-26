use serde_json::Value;

#[derive(Debug)]
pub struct AstNode {
    pub node_type: String,
    pub children: Vec<AstNode>,
    pub raw: Value,
}

pub struct Parser;

impl Parser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_ast(_json: &Value) -> Result<AstNode, anyhow::Error> {
        todo!("Parse Solidity AST from JSON")
    }
}
