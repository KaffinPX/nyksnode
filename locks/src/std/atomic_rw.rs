use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;

use super::shared::LockAcquisition;
use super::traits::Atomic;
use super::LockCallbackFn;
use super::LockCallbackInfo;
use super::LockEvent;
use super::LockType;

/// An `Arc<RwLock<T>>` wrapper to make data thread-safe and easy to work with.
#[derive(Debug)]
pub struct AtomicRw<T> {
    inner: Arc<RwLock<T>>,
    lock_callback_info: LockCallbackInfo,
}

impl<T: Default> Default for AtomicRw<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}

impl<T> From<T> for AtomicRw<T> {
    #[inline]
    fn from(t: T) -> Self {
        Self {
            inner: Arc::new(RwLock::new(t)),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}
impl<T> From<(T, Option<String>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from an optional name and an optional callback function, which
    /// is called when a lock is event occurs.
    #[inline]
    fn from(v: (T, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(RwLock::new(v.0)),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, v.1, v.2),
        }
    }
}
impl<T> From<(T, Option<&str>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from a name ref and an optional callback function, which
    /// is called when a lock event occurs.
    #[inline]
    fn from(v: (T, Option<&str>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(RwLock::new(v.0)),
            lock_callback_info: LockCallbackInfo::new(
                LockType::RwLock,
                v.1.map(|s| s.to_owned()),
                v.2,
            ),
        }
    }
}

impl<T> Clone for AtomicRw<T> {
    fn clone(&self) -> Self {
        Self {
            lock_callback_info: self.lock_callback_info.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<T> From<RwLock<T>> for AtomicRw<T> {
    #[inline]
    fn from(t: RwLock<T>) -> Self {
        Self {
            inner: Arc::new(t),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}
impl<T> From<(RwLock<T>, Option<String>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from an `RwLock<T>` plus an optional name
    /// and an optional callback function, which is called
    /// when a lock event occurs.
    #[inline]
    fn from(v: (RwLock<T>, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(v.0),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, v.1, v.2),
        }
    }
}

impl<T> TryFrom<AtomicRw<T>> for RwLock<T> {
    type Error = Arc<RwLock<T>>;
    fn try_from(t: AtomicRw<T>) -> Result<RwLock<T>, Self::Error> {
        Arc::<RwLock<T>>::try_unwrap(t.inner)
    }
}

impl<T> From<Arc<RwLock<T>>> for AtomicRw<T> {
    #[inline]
    fn from(t: Arc<RwLock<T>>) -> Self {
        Self {
            inner: t,
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}
impl<T> From<(Arc<RwLock<T>>, Option<String>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from an `Arc<RwLock<T>>` plus an optional name and
    /// an optional callback function, which is called when a lock
    /// event occurs.
    #[inline]
    fn from(v: (Arc<RwLock<T>>, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: v.0,
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, v.1, v.2),
        }
    }
}

impl<T> From<AtomicRw<T>> for Arc<RwLock<T>> {
    #[inline]
    fn from(t: AtomicRw<T>) -> Self {
        t.inner
    }
}

// note: we impl the Atomic trait methods here also so they
// can be used without caller having to use the trait.
impl<T> AtomicRw<T> {
    /// Acquire read lock and return an `RwLockReadGuard`
    pub fn lock_guard(&self) -> AtomicRwReadGuard<'_, T> {
        self.try_acquire_read_cb();
        let guard = self.inner.read().expect("Read lock should succeed");
        AtomicRwReadGuard::new(guard, &self.lock_callback_info)
    }

    /// Acquire write lock and return an `RwLockWriteGuard`
    pub fn lock_guard_mut(&mut self) -> AtomicRwWriteGuard<'_, T> {
        self.try_acquire_write_cb();
        let guard = self.inner.write().expect("Write lock should succeed");
        AtomicRwWriteGuard::new(guard, &self.lock_callback_info)
    }

    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    pub fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        self.try_acquire_read_cb();
        let guard = self.inner.read().expect("Read lock should succeed");
        let my_guard = AtomicRwReadGuard::new(guard, &self.lock_callback_info);
        f(&my_guard)
    }

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    pub fn lock_mut<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        self.try_acquire_write_cb();
        let guard = self.inner.write().expect("Write lock should succeed");
        let mut my_guard = AtomicRwWriteGuard::new(guard, &self.lock_callback_info);
        f(&mut my_guard)
    }

    /// get copy of the locked value T (if T implements Copy).
    #[inline]
    pub fn get(&self) -> T
    where
        T: Copy,
    {
        self.lock(|v| *v)
    }

    /// set the locked value T (if T implements Copy).
    #[inline]
    pub fn set(&mut self, value: T)
    where
        T: Copy,
    {
        self.lock_mut(|v| *v = value)
    }

    /// retrieve lock name if present, or None
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.lock_callback_info.lock_info_owned.name.as_deref()
    }

    fn try_acquire_read_cb(&self) {
        if let Some(cb) = self.lock_callback_info.lock_callback_fn {
            cb(LockEvent::TryAcquire {
                info: self.lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Read,
            });
        }
    }

    fn try_acquire_write_cb(&self) {
        if let Some(cb) = self.lock_callback_info.lock_callback_fn {
            cb(LockEvent::TryAcquire {
                info: self.lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Write,
            });
        }
    }
}

impl<T> Atomic<T> for AtomicRw<T> {
    #[inline]
    fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        AtomicRw::<T>::lock(self, f)
    }

    #[inline]
    fn lock_mut<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        AtomicRw::<T>::lock_mut(self, f)
    }
}

/// A wrapper for [RwLockReadGuard] that can optionally call a callback to
/// notify when a lock event occurs.
#[derive(Debug)]
pub struct AtomicRwReadGuard<'a, T> {
    guard: RwLockReadGuard<'a, T>,
    lock_callback_info: &'a LockCallbackInfo,
}

impl<'a, T> AtomicRwReadGuard<'a, T> {
    fn new(guard: RwLockReadGuard<'a, T>, lock_callback_info: &'a LockCallbackInfo) -> Self {
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Acquire {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Read,
            });
        }
        Self {
            guard,
            lock_callback_info,
        }
    }
}

impl<T> Drop for AtomicRwReadGuard<'_, T> {
    fn drop(&mut self) {
        let lock_callback_info = self.lock_callback_info;
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Release {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Read,
            });
        }
    }
}

impl<T> Deref for AtomicRwReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

/// A wrapper for [RwLockWriteGuard] that can optionally call a callback to
/// notify when a lock event occurs.
#[derive(Debug)]
pub struct AtomicRwWriteGuard<'a, T> {
    guard: RwLockWriteGuard<'a, T>,
    lock_callback_info: &'a LockCallbackInfo,
}

impl<'a, T> AtomicRwWriteGuard<'a, T> {
    fn new(guard: RwLockWriteGuard<'a, T>, lock_callback_info: &'a LockCallbackInfo) -> Self {
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Acquire {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Write,
            });
        }
        Self {
            guard,
            lock_callback_info,
        }
    }
}

impl<T> Drop for AtomicRwWriteGuard<'_, T> {
    fn drop(&mut self) {
        let lock_callback_info = self.lock_callback_info;
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Release {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Write,
            });
        }
    }
}

impl<T> Deref for AtomicRwWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for AtomicRwWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Verify (compile-time) that AtomicRw::lock() and ::lock_mut() accept
    /// mutable values. (FnMut)
    #[test]
    fn mutable_assignment() {
        let name = "Jim".to_string();
        let mut atomic_name = AtomicRw::from(name);

        let mut new_name = String::new();
        atomic_name.lock(|n| new_name = n.to_string());
        atomic_name.lock_mut(|n| new_name = (*n).to_string());
    }
}
