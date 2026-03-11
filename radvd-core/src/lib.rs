//! radvd-core - Core library for radvd (Router Advertisement Daemon)
//!
//! This library provides the core functionality for the radvd daemon,
//! including configuration structures, network packet handling, and
//! protocol implementations.

pub mod config;
pub mod constants;
pub mod error;
pub mod interface;
pub mod parser;
pub mod ra;
pub mod socket;
pub mod timer;
pub mod types;
pub mod util;

pub use error::{RadvdError, RadvdResult};
