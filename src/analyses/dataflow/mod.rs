// Dataflow analysis framework

pub trait Lattice {
    fn join(&mut self, other: &Self);
    fn meet(&mut self, other: &Self);
}

pub enum Direction {
    Forward,
    Backward,
}

pub struct DataflowFramework<T: Lattice> {
    pub direction: Direction,
    _marker: std::marker::PhantomData<T>,
}

impl<T: Lattice> DataflowFramework<T> {
    pub fn new(direction: Direction) -> Self {
        Self {
            direction,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn solve(&mut self) {
        // TODO: Implement fixpoint iteration
        todo!()
    }
}
