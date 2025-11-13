//! Socket address handling
//!
//! This module provides a safe, idiomatic Rust interface for working with socket addresses.
//! It's equivalent to the C `vsa.c` module, providing a clean abstraction over the messy
//! sockaddr family of types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{Error, Result};

/// A socket address that can represent IPv4, IPv6, or Unix domain socket addresses.
///
/// This is the Rust equivalent of C's `struct suckaddr`, providing type-safe
/// handling of different address families.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockAddr {
    /// IPv4 socket address
    V4(std::net::SocketAddrV4),
    /// IPv6 socket address
    V6(std::net::SocketAddrV6),
    /// Unix domain socket address
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl SockAddr {
    /// Create a new IPv4 socket address
    pub fn new_v4(ip: Ipv4Addr, port: u16) -> Self {
        SockAddr::V4(std::net::SocketAddrV4::new(ip, port))
    }

    /// Create a new IPv6 socket address
    pub fn new_v6(ip: Ipv6Addr, port: u16) -> Self {
        SockAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
    }

    /// Create from a standard library SocketAddr
    pub fn from_std(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => SockAddr::V4(v4),
            SocketAddr::V6(v6) => SockAddr::V6(v6),
        }
    }

    /// Convert to standard library SocketAddr if possible
    ///
    /// Returns None for Unix domain sockets
    pub fn to_std(&self) -> Option<SocketAddr> {
        match self {
            SockAddr::V4(v4) => Some(SocketAddr::V4(*v4)),
            SockAddr::V6(v6) => Some(SocketAddr::V6(*v6)),
            #[cfg(unix)]
            SockAddr::Unix(_) => None,
        }
    }

    /// Get the port number
    ///
    /// Returns 0 for Unix domain sockets
    pub fn port(&self) -> u16 {
        match self {
            SockAddr::V4(v4) => v4.port(),
            SockAddr::V6(v6) => v6.port(),
            #[cfg(unix)]
            SockAddr::Unix(_) => 0,
        }
    }

    /// Get the IP address if this is an IP socket
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            SockAddr::V4(v4) => Some(IpAddr::V4(*v4.ip())),
            SockAddr::V6(v6) => Some(IpAddr::V6(*v6.ip())),
            #[cfg(unix)]
            SockAddr::Unix(_) => None,
        }
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, SockAddr::V4(_))
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, SockAddr::V6(_))
    }

    /// Check if this is a Unix domain socket address
    #[cfg(unix)]
    pub fn is_unix(&self) -> bool {
        matches!(self, SockAddr::Unix(_))
    }

    /// Compare only the IP addresses, ignoring ports
    ///
    /// Returns false if comparing different address families or Unix sockets
    pub fn compare_ip(&self, other: &Self) -> bool {
        match (self.ip(), other.ip()) {
            (Some(ip1), Some(ip2)) => ip1 == ip2,
            _ => false,
        }
    }

    /// Get address family as a string
    pub fn family(&self) -> &'static str {
        match self {
            SockAddr::V4(_) => "IPv4",
            SockAddr::V6(_) => "IPv6",
            #[cfg(unix)]
            SockAddr::Unix(_) => "Unix",
        }
    }

    /// Format address as string (without port)
    pub fn addr_string(&self) -> String {
        match self {
            SockAddr::V4(v4) => v4.ip().to_string(),
            SockAddr::V6(v6) => {
                let ip = v6.ip();
                // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
                if let Some(ipv4) = ip.to_ipv4_mapped() {
                    ipv4.to_string()
                } else {
                    ip.to_string()
                }
            }
            #[cfg(unix)]
            SockAddr::Unix(path) => path.to_string_lossy().to_string(),
        }
    }

    /// Format port as string
    pub fn port_string(&self) -> String {
        self.port().to_string()
    }

    /// Create a "bogus" IPv4 address (0.0.0.0:0) for testing
    pub fn bogus_v4() -> Self {
        SockAddr::new_v4(Ipv4Addr::UNSPECIFIED, 0)
    }

    /// Create a "bogus" IPv6 address (:::0) for testing
    pub fn bogus_v6() -> Self {
        SockAddr::new_v6(Ipv6Addr::UNSPECIFIED, 0)
    }
}

impl fmt::Display for SockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SockAddr::V4(v4) => write!(f, "{}", v4),
            SockAddr::V6(v6) => write!(f, "{}", v6),
            #[cfg(unix)]
            SockAddr::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl From<SocketAddr> for SockAddr {
    fn from(addr: SocketAddr) -> Self {
        SockAddr::from_std(addr)
    }
}

impl From<std::net::SocketAddrV4> for SockAddr {
    fn from(addr: std::net::SocketAddrV4) -> Self {
        SockAddr::V4(addr)
    }
}

impl From<std::net::SocketAddrV6> for SockAddr {
    fn from(addr: std::net::SocketAddrV6) -> Self {
        SockAddr::V6(addr)
    }
}

impl TryFrom<SockAddr> for SocketAddr {
    type Error = Error;

    fn try_from(addr: SockAddr) -> Result<Self> {
        addr.to_std()
            .ok_or_else(|| Error::UnsupportedFamily("Cannot convert Unix socket to SocketAddr".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_basic() {
        let addr = SockAddr::new_v4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.family(), "IPv4");
        assert_eq!(addr.addr_string(), "127.0.0.1");
        assert_eq!(addr.port_string(), "8080");
    }

    #[test]
    fn test_ipv6_basic() {
        let addr = SockAddr::new_v6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080);
        assert!(!addr.is_ipv4());
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.family(), "IPv6");
        assert_eq!(addr.port_string(), "8080");
    }

    #[test]
    fn test_ipv4_mapped() {
        // ::ffff:127.0.0.1
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001);
        let addr = SockAddr::new_v6(ipv6, 8080);
        // Should be displayed as IPv4
        assert_eq!(addr.addr_string(), "127.0.0.1");
    }

    #[test]
    fn test_compare_ip() {
        let addr1 = SockAddr::new_v4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let addr2 = SockAddr::new_v4(Ipv4Addr::new(127, 0, 0, 1), 9090);
        let addr3 = SockAddr::new_v4(Ipv4Addr::new(127, 0, 0, 2), 8080);

        assert!(addr1.compare_ip(&addr2)); // Same IP, different port
        assert!(!addr1.compare_ip(&addr3)); // Different IP
    }

    #[test]
    fn test_bogus_addresses() {
        let bogus_v4 = SockAddr::bogus_v4();
        assert_eq!(bogus_v4.port(), 0);
        assert_eq!(bogus_v4.addr_string(), "0.0.0.0");

        let bogus_v6 = SockAddr::bogus_v6();
        assert_eq!(bogus_v6.port(), 0);
        assert_eq!(bogus_v6.addr_string(), "::");
    }

    #[test]
    fn test_conversions() {
        let std_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let sock_addr = SockAddr::from_std(std_addr);
        assert!(sock_addr.is_ipv4());
        assert_eq!(sock_addr.port(), 8080);

        let back_to_std = sock_addr.to_std().unwrap();
        assert_eq!(back_to_std, std_addr);
    }

    #[test]
    fn test_display() {
        let addr = SockAddr::new_v4(Ipv4Addr::new(192, 168, 1, 1), 80);
        assert_eq!(addr.to_string(), "192.168.1.1:80");
    }
}
