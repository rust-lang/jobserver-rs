use std::ops::Deref;

#[derive(Debug)]
#[allow(unused)]
pub enum MaybeOwned<'a, T> {
    Owned(T),
    Borrowed(&'a T),
}

impl<T> Deref for MaybeOwned<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        use MaybeOwned::*;

        match self {
            Owned(val) => val,
            Borrowed(val) => val,
        }
    }
}
