use crate::analyses::Analysis;

pub struct TaintSource {
    pub id: String,
}

pub struct TaintSink {
    pub id: String,
}

pub struct TaintSanitizer {
    pub id: String,
}

pub struct TaintAnalysis {
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub sanitizers: Vec<TaintSanitizer>,
}

impl Analysis for TaintAnalysis {
    type Output = ();

    fn run(&mut self) -> Self::Output {
        // TODO: Implement taint analysis with source/sink/sanitizer model
        todo!()
    }
}
