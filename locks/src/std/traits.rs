//! Traits that define the [`locks::std`](crate::application::locks::std)
//! interface

pub trait Atomic<T> {
    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R;

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    fn lock_mut<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R;

    /// get copy of the locked value T (if T implements Copy).
    #[inline]
    fn get(&self) -> T
    where
        T: Copy,
    {
        self.lock(|v| *v)
    }

    /// set the locked value T (if T implements Copy).
    #[inline]
    fn set(&mut self, value: T)
    where
        T: Copy,
    {
        self.lock_mut(|v| *v = value)
    }
}
