use crate::analyses::Analysis;

pub struct StorageLayoutAnalysis;

impl Analysis for StorageLayoutAnalysis {
    type Output = ();

    fn run(&mut self) -> Self::Output {
        // TODO: Implement storage layout analysis
        todo!()
    }
}
