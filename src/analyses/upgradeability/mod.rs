use crate::analyses::Analysis;

pub struct UpgradeabilityAnalysis;

impl Analysis for UpgradeabilityAnalysis {
    type Output = ();

    fn run(&mut self) -> Self::Output {
        // TODO: Implement proxy/upgrade pattern detection
        todo!()
    }
}
