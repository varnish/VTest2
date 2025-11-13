//! DNS resolution and address parsing
//!
//! This module provides address parsing and DNS resolution functionality.
//! It's equivalent to the C `vss.c` module.
//!
//! Supported address formats:
//! - "localhost" - "localhost:80" - "localhost 80"
//! - "127.0.0.1" - "127.0.0.1:80" - "127.0.0.1 80"
//! - "0.0.0.0"   - "0.0.0.0:80"   - "0.0.0.0 80"
//! - "[::1]"     - "[::1]:80"     - "[::1] 80"
//! - "[::]"      - "[::]:80"      - "[::] 80"
//! - "::1"       - "[::1]:80"     - "[::1] 80"
//!
//! Port ranges are also supported:
//! - "localhost:8000-8010" - bind to ports 8000 through 8010

use std::net::{SocketAddr, ToSocketAddrs};

use super::{Error, Result, SockAddr};

/// Parsed address components
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddress {
    /// The host part (IP address or hostname)
    pub host: Option<String>,
    /// The port part (can be a single port or a range)
    pub port: PortSpec,
}

/// Port specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    /// No port specified
    None,
    /// Single port
    Single(u16),
    /// Port range (inclusive)
    Range(u16, u16),
    /// Port string that needs resolution (e.g., "http")
    String(String),
}

/// Address parser for handling various address formats
pub struct AddressParser;

impl AddressParser {
    /// Parse an address string into host and port components
    ///
    /// # Examples
    /// ```
    /// use vtest2::net::resolver::AddressParser;
    ///
    /// let parsed = AddressParser::parse("localhost:8080", None).unwrap();
    /// assert_eq!(parsed.host.as_deref(), Some("localhost"));
    /// ```
    pub fn parse(addr: &str, default_port: Option<&str>) -> Result<ParsedAddress> {
        let (host, port) = Self::split_address(addr)?;

        let port_spec = if let Some(port_str) = port {
            Self::parse_port(port_str)?
        } else if let Some(def_port) = default_port {
            Self::parse_port(def_port)?
        } else {
            PortSpec::None
        };

        Ok(ParsedAddress {
            host: host.map(String::from),
            port: port_spec,
        })
    }

    /// Split an address string into host and port parts
    fn split_address(addr: &str) -> Result<(Option<&str>, Option<&str>)> {
        let addr = addr.trim();

        if addr.is_empty() {
            return Err(Error::InvalidAddress("Empty address".to_string()));
        }

        // Handle IPv6 addresses in brackets: [::1]:80 or [::1] 80
        if addr.starts_with('[') {
            let close_bracket = addr.find(']')
                .ok_or_else(|| Error::InvalidAddress("IPv6 address lacks ']'".to_string()))?;

            let host = &addr[1..close_bracket];
            let rest = &addr[close_bracket + 1..];

            if rest.is_empty() {
                return Ok((Some(host), None));
            }

            let separator = rest.chars().next().unwrap();
            if separator != ' ' && separator != ':' {
                return Err(Error::InvalidAddress(
                    "IPv6 address has wrong port separator".to_string()
                ));
            }

            let port = rest[1..].trim();
            return Ok((
                Some(host),
                if port.is_empty() { None } else { Some(port) }
            ));
        }

        // Handle IPv4 or hostname with space separator
        if let Some(space_pos) = addr.find(' ') {
            let host = &addr[..space_pos];
            let port = addr[space_pos + 1..].trim();
            return Ok((
                if host.is_empty() { None } else { Some(host) },
                if port.is_empty() { None } else { Some(port) }
            ));
        }

        // Handle IPv4 or hostname with colon separator
        if let Some(colon_pos) = addr.find(':') {
            // Check if there are multiple colons (IPv6 without brackets)
            if addr[colon_pos + 1..].contains(':') {
                // IPv6 address without port
                return Ok((Some(addr), None));
            }

            let host = &addr[..colon_pos];
            let port = &addr[colon_pos + 1..];
            return Ok((
                if host.is_empty() { None } else { Some(host) },
                if port.is_empty() { None } else { Some(port) }
            ));
        }

        // No separator found, just a host
        Ok((Some(addr), None))
    }

    /// Parse a port specification (single port, range, or service name)
    fn parse_port(port_str: &str) -> Result<PortSpec> {
        // Check for port range (e.g., "8000-8010")
        if let Some(dash_pos) = port_str.find('-') {
            let start_str = &port_str[..dash_pos];
            let end_str = &port_str[dash_pos + 1..];

            // Check for multiple dashes
            if end_str.contains('-') {
                return Err(Error::InvalidPortRange(
                    "Multiple dashes in port range".to_string()
                ));
            }

            if start_str.is_empty() || end_str.is_empty() {
                return Err(Error::InvalidPortRange(
                    "Empty port in range".to_string()
                ));
            }

            let start: u16 = start_str.parse()
                .map_err(|_| Error::InvalidPortRange(
                    format!("Invalid start port: {}", start_str)
                ))?;

            let end: u16 = end_str.parse()
                .map_err(|_| Error::InvalidPortRange(
                    format!("Invalid end port: {}", end_str)
                ))?;

            if start == 0 {
                return Err(Error::InvalidPortRange(
                    "Range start cannot be 0".to_string()
                ));
            }

            if end < start {
                return Err(Error::InvalidPortRange(
                    "Range start higher than range end".to_string()
                ));
            }

            return Ok(PortSpec::Range(start, end));
        }

        // Try to parse as a number
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok(PortSpec::Single(port));
        }

        // Otherwise, treat as a service name
        Ok(PortSpec::String(port_str.to_string()))
    }
}

/// Iterator over resolved socket addresses
pub struct ResolveIter {
    addresses: Vec<SockAddr>,
    index: usize,
}

impl ResolveIter {
    /// Resolve an address string to socket addresses
    ///
    /// # Examples
    /// ```
    /// use vtest2::net::resolver::ResolveIter;
    ///
    /// let addrs: Vec<_> = ResolveIter::resolve("localhost:8080", None)
    ///     .unwrap()
    ///     .collect();
    /// assert!(!addrs.is_empty());
    /// ```
    pub fn resolve(addr: &str, default_port: Option<&str>) -> Result<Self> {
        let parsed = AddressParser::parse(addr, default_port)?;

        match parsed.port {
            PortSpec::Range(start, end) => {
                Self::resolve_range(&parsed.host, start, end)
            }
            _ => {
                let addresses = Self::resolve_single(&parsed)?;
                Ok(ResolveIter { addresses, index: 0 })
            }
        }
    }

    /// Resolve a single address (no port range)
    fn resolve_single(parsed: &ParsedAddress) -> Result<Vec<SockAddr>> {
        let host = parsed.host.as_deref().unwrap_or("0.0.0.0");

        let port_str = match &parsed.port {
            PortSpec::None => "0",
            PortSpec::Single(p) => return Self::resolve_with_port(host, *p),
            PortSpec::String(s) => s.as_str(),
            PortSpec::Range(_, _) => unreachable!(),
        };

        // Use standard library DNS resolution
        let addr_str = format!("{}:{}", host, port_str);
        let std_addrs: Vec<SocketAddr> = addr_str.to_socket_addrs()
            .map_err(|e| Error::ResolutionFailed(e.to_string()))?
            .collect();

        if std_addrs.is_empty() {
            return Err(Error::ResolutionFailed(
                format!("No addresses found for {}", addr_str)
            ));
        }

        Ok(std_addrs.into_iter().map(SockAddr::from_std).collect())
    }

    /// Resolve an address with a specific numeric port
    fn resolve_with_port(host: &str, port: u16) -> Result<Vec<SockAddr>> {
        let addr_str = format!("{}:0", host);
        let std_addrs: Vec<SocketAddr> = addr_str.to_socket_addrs()
            .map_err(|e| Error::ResolutionFailed(e.to_string()))?
            .collect();

        if std_addrs.is_empty() {
            return Err(Error::ResolutionFailed(
                format!("No addresses found for {}", host)
            ));
        }

        // Replace port 0 with the actual port
        let addrs = std_addrs.into_iter().map(|mut addr| {
            addr.set_port(port);
            SockAddr::from_std(addr)
        }).collect();

        Ok(addrs)
    }

    /// Resolve a port range
    fn resolve_range(host: &Option<String>, start: u16, end: u16) -> Result<Self> {
        let host = host.as_deref().unwrap_or("0.0.0.0");
        let mut addresses = Vec::new();

        for port in start..=end {
            match Self::resolve_with_port(host, port) {
                Ok(mut addrs) => addresses.append(&mut addrs),
                Err(_) => continue, // Skip ports that fail to resolve
            }
        }

        if addresses.is_empty() {
            return Err(Error::ResolutionFailed(
                format!("No addresses resolved for {}:{}-{}", host, start, end)
            ));
        }

        Ok(ResolveIter { addresses, index: 0 })
    }

    /// Resolve and return only the first address
    pub fn resolve_first(addr: &str, default_port: Option<&str>) -> Result<SockAddr> {
        let mut iter = Self::resolve(addr, default_port)?;
        iter.next().ok_or_else(|| {
            Error::ResolutionFailed("No addresses resolved".to_string())
        })
    }

    /// Resolve and return exactly one address (fails if multiple)
    pub fn resolve_one(addr: &str, default_port: Option<&str>) -> Result<SockAddr> {
        let iter = Self::resolve(addr, default_port)?;
        let addresses: Vec<_> = iter.collect();

        if addresses.len() != 1 {
            return Err(Error::ResolutionFailed(
                format!("Expected exactly one address, got {}", addresses.len())
            ));
        }

        Ok(addresses.into_iter().next().unwrap())
    }
}

impl Iterator for ResolveIter {
    type Item = SockAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.addresses.len() {
            let addr = self.addresses[self.index].clone();
            self.index += 1;
            Some(addr)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_with_colon() {
        let parsed = AddressParser::parse("127.0.0.1:8080", None).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(parsed.port, PortSpec::Single(8080));
    }

    #[test]
    fn test_parse_ipv4_with_space() {
        let parsed = AddressParser::parse("127.0.0.1 8080", None).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(parsed.port, PortSpec::Single(8080));
    }

    #[test]
    fn test_parse_ipv6_brackets() {
        let parsed = AddressParser::parse("[::1]:8080", None).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("::1"));
        assert_eq!(parsed.port, PortSpec::Single(8080));
    }

    #[test]
    fn test_parse_ipv6_no_port() {
        let parsed = AddressParser::parse("::1", None).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("::1"));
        assert_eq!(parsed.port, PortSpec::None);
    }

    #[test]
    fn test_parse_hostname() {
        let parsed = AddressParser::parse("localhost:80", None).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("localhost"));
        assert_eq!(parsed.port, PortSpec::Single(80));
    }

    #[test]
    fn test_parse_default_port() {
        let parsed = AddressParser::parse("localhost", Some("8080")).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("localhost"));
        assert_eq!(parsed.port, PortSpec::Single(8080));
    }

    #[test]
    fn test_parse_port_range() {
        let parsed = AddressParser::parse("localhost:8000-8010", None).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("localhost"));
        assert_eq!(parsed.port, PortSpec::Range(8000, 8010));
    }

    #[test]
    fn test_parse_invalid_port_range() {
        assert!(AddressParser::parse("localhost:8010-8000", None).is_err());
        assert!(AddressParser::parse("localhost:0-100", None).is_err());
    }

    #[test]
    fn test_resolve_localhost() {
        let addrs: Vec<_> = ResolveIter::resolve("localhost:8080", None)
            .unwrap()
            .collect();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].port(), 8080);
    }

    #[test]
    fn test_resolve_ipv4() {
        let addrs: Vec<_> = ResolveIter::resolve("127.0.0.1:9090", None)
            .unwrap()
            .collect();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 9090);
        assert!(addrs[0].is_ipv4());
    }

    #[test]
    fn test_resolve_first() {
        let addr = ResolveIter::resolve_first("127.0.0.1:7070", None).unwrap();
        assert_eq!(addr.port(), 7070);
    }

    #[test]
    fn test_resolve_range() {
        let addrs: Vec<_> = ResolveIter::resolve("127.0.0.1:8000-8002", None)
            .unwrap()
            .collect();
        // Should have 3 addresses (8000, 8001, 8002) per resolved IP
        assert!(!addrs.is_empty());
        assert!(addrs.len() >= 3);
    }
}
