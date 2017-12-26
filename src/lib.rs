//! This is an implementation of Twisted Banana protocol family
//! (see https://twistedmatrix.com/documents/current/core/specifications/banana.html)
//! It provides the plain Banana and the Perspective Broker message protocols.
//! The ultimate goal of this lib is to provide helpers for interoperability between
//! Rust and Twisted applications.

mod banana;
mod pb;

pub use banana::{Profile, DecodeError, Banana, Element, NoneProfile};
pub use pb::{PerspectiveBroker, PB};
