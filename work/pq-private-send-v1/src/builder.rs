//! Restrict the upstream AIR to its exact column window, without editing it.
use p3_air::{AirBuilder, WindowAccess};
#[derive(Clone)]
pub struct SliceWindow<W> { pub inner: W, pub start: usize, pub len: usize }
impl<T, W: WindowAccess<T>> WindowAccess<T> for SliceWindow<W> {
    fn current_slice(&self) -> &[T] { &self.inner.current_slice()[self.start..self.start+self.len] }
    fn next_slice(&self) -> &[T] { &self.inner.next_slice()[self.start..self.start+self.len] }
}
pub struct SliceBuilder<'a, AB> { pub inner: &'a mut AB, pub start: usize, pub len: usize }
impl<AB: AirBuilder> AirBuilder for SliceBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = SliceWindow<AB::MainWindow>;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow { SliceWindow {inner:self.inner.main(), start:self.start, len:self.len} }
    fn preprocessed(&self) -> &Self::PreprocessedWindow { self.inner.preprocessed() }
    fn is_first_row(&self) -> Self::Expr { self.inner.is_first_row() }
    fn is_last_row(&self) -> Self::Expr { self.inner.is_last_row() }
    fn is_transition(&self) -> Self::Expr { self.inner.is_transition() }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x:I) { self.inner.assert_zero(x); }
    fn public_values(&self) -> &[Self::PublicVar] { self.inner.public_values() }
    fn periodic_values(&self) -> &[Self::PeriodicVar] { self.inner.periodic_values() }
}
