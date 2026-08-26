use crate::analyses::Analysis;

pub struct AuthorizationAnalysis;

impl Analysis for AuthorizationAnalysis {
    type Output = ();

    fn run(&mut self) -> Self::Output {
        // TODO: Implement access control analysis (tracking msg.sender checks, modifiers)
        todo!()
    }
}
