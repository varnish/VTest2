//! Network utilities for VTest2
//!
//! This module provides idiomatic Rust interfaces for TCP socket operations,
//! address handling, and DNS resolution. It's a port of the C network utilities
//! from Varnish Cache (vtcp, vsa, vss).

pub mod addr;
pub mod resolver;
pub mod tcp;

pub use addr::SockAddr;
pub use resolver::{AddressParser, ResolveIter};
pub use tcp::{TcpConnector, TcpExt, TcpListenerBuilder, TcpListenerExt};

/// Result type for network operations
pub type Result<T> = std::result::Result<T, Error>;

/// Network operation errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("Address resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Invalid port range: {0}")]
    InvalidPortRange(String),

    #[error("Unsupported address family: {0}")]
    UnsupportedFamily(String),
}
