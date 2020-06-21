use thiserror::Error;
use std::fmt;

#[derive(Debug, Error, Eq, PartialEq, Copy, Clone)]
pub enum ErrorKind {
    InvalidFormat,
    Checksum,
}

#[derive(Debug, Error, Eq, PartialEq, Copy, Clone)]
pub struct Error {
    inner: ErrorKind
}

// impl Error {
//     /// Return true if the underlying error has the same type as T.
//     // pub fn is<T: error::Error + 'static>(&self) -> bool {
//     //     self.get_ref().is::<T>()
//     // }
//
//     /// Return a reference to the lower level, inner error.
//     // pub fn get_ref(&self) -> &(dyn error::Error + 'static) {
//     //     use self::ErrorKind::*;
//     //
//     //     match self.inner {
//     //         InvalidFormat
//     //     }
//     // }
// }

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("packet error kind")
    }
}

impl std::convert::From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: kind
        }
    }
}