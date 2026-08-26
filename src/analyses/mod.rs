pub mod cfg;
pub mod dataflow;
pub mod taint;
pub mod callgraph;
pub mod storage;
pub mod authorization;
pub mod upgradeability;

pub trait Analysis {
    type Output;
    fn run(&mut self) -> Self::Output;
}
