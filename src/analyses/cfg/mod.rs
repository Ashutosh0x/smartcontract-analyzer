// Assume petgraph is added in Cargo.toml
// use petgraph::graph::DiGraph;

use crate::analyses::Analysis;

pub struct CfgNode {
    pub id: usize,
    pub code: String,
}

pub struct CfgEdge {
    pub kind: EdgeKind,
}

pub enum EdgeKind {
    Normal,
    TrueBranch,
    FalseBranch,
}

pub struct CfgAnalysis;

impl Analysis for CfgAnalysis {
    type Output = (); // TODO: petgraph::graph::DiGraph<CfgNode, CfgEdge>;

    fn run(&mut self) -> Self::Output {
        // TODO: Implement CFG construction
        todo!()
    }
}
