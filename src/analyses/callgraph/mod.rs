use crate::analyses::Analysis;

pub struct CallGraphAnalysis;

impl Analysis for CallGraphAnalysis {
    type Output = ();

    fn run(&mut self) -> Self::Output {
        // TODO: Implement call graph construction
        todo!()
    }
}
