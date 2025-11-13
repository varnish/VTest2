//! TCP socket utilities
//!
//! This module provides TCP-specific operations and extensions.
//! It's equivalent to the C `vtcp.c` module.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use socket2::{Socket, Domain, Type, Protocol, SockAddr as Socket2Addr};

use super::{Error, Result, SockAddr, ResolveIter};

/// Extension trait for TcpStream with additional utilities
pub trait TcpExt {
    /// Set TCP_NODELAY option
    fn set_nodelay(&self, nodelay: bool) -> Result<()>;

    /// Set socket to blocking or non-blocking mode
    fn set_blocking(&self, blocking: bool) -> Result<()>;

    /// Set SO_LINGER option
    fn set_linger(&self, duration: Option<Duration>) -> Result<()>;

    /// Set SO_KEEPALIVE option
    fn set_keepalive(&self, keepalive: bool) -> Result<()>;

    /// Set read timeout
    fn set_read_timeout_dur(&self, timeout: Option<Duration>) -> Result<()>;

    /// Set write timeout
    fn set_write_timeout_dur(&self, timeout: Option<Duration>) -> Result<()>;

    /// Get local socket address as SockAddr
    fn local_sockaddr(&self) -> Result<SockAddr>;

    /// Get peer socket address as SockAddr
    fn peer_sockaddr(&self) -> Result<SockAddr>;

    /// Check if the connection has been closed by the peer (HUP)
    fn check_hup(&self) -> Result<bool>;

    /// Read with timeout, returns number of bytes read or error
    ///
    /// Returns:
    /// - Ok(n) where n > 0: Successfully read n bytes
    /// - Ok(0): EOF reached
    /// - Err(Error::Timeout): Timeout occurred
    /// - Err(other): Other I/O error
    fn read_with_timeout(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize>;
}

impl TcpExt for TcpStream {
    fn set_nodelay(&self, nodelay: bool) -> Result<()> {
        TcpStream::set_nodelay(self, nodelay).map_err(Error::from)
    }

    fn set_blocking(&self, blocking: bool) -> Result<()> {
        self.set_nonblocking(!blocking).map_err(Error::from)
    }

    fn set_linger(&self, duration: Option<Duration>) -> Result<()> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let fd = self.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(fd) };
        let result = socket.set_linger(duration).map_err(Error::from);
        let _ = socket.into_raw_fd(); // Don't close the fd
        result
    }

    fn set_keepalive(&self, keepalive: bool) -> Result<()> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let fd = self.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(fd) };
        let result = socket.set_keepalive(keepalive).map_err(Error::from);
        let _ = socket.into_raw_fd();
        result
    }

    fn set_read_timeout_dur(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_read_timeout(timeout).map_err(Error::from)
    }

    fn set_write_timeout_dur(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_timeout(timeout).map_err(Error::from)
    }

    fn local_sockaddr(&self) -> Result<SockAddr> {
        let addr = self.local_addr().map_err(Error::from)?;
        Ok(SockAddr::from_std(addr))
    }

    fn peer_sockaddr(&self) -> Result<SockAddr> {
        let addr = self.peer_addr().map_err(Error::from)?;
        Ok(SockAddr::from_std(addr))
    }

    fn check_hup(&self) -> Result<bool> {
        use libc::{poll, pollfd, POLLHUP, POLLOUT};

        let fd = self.as_raw_fd();
        let mut pfd = pollfd {
            fd,
            events: POLLOUT,
            revents: 0,
        };

        let ret = unsafe { poll(&mut pfd, 1, 0) };

        if ret < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        Ok(ret == 1 && (pfd.revents & POLLHUP) != 0)
    }

    fn read_with_timeout(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize> {
        if let Some(timeout) = timeout {
            use libc::{poll, pollfd, POLLIN};

            let fd = self.as_raw_fd();
            let mut pfd = pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            };

            let timeout_ms = timeout.as_millis() as i32;
            let ret = unsafe { poll(&mut pfd, 1, timeout_ms) };

            if ret < 0 {
                return Err(Error::Io(io::Error::last_os_error()));
            }

            if ret == 0 {
                return Err(Error::Timeout);
            }
        }

        self.read(buf).map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                Error::Timeout
            } else {
                Error::from(e)
            }
        })
    }
}

/// Extension trait for TcpListener with additional utilities
pub trait TcpListenerExt {
    /// Set SO_REUSEADDR option
    fn set_reuseaddr(&self, reuse: bool) -> Result<()>;

    /// Set TCP_DEFER_ACCEPT option (Linux only)
    #[cfg(target_os = "linux")]
    fn set_defer_accept(&self, timeout: Duration) -> Result<()>;

    /// Get local socket address as SockAddr
    fn local_sockaddr(&self) -> Result<SockAddr>;
}

impl TcpListenerExt for TcpListener {
    fn set_reuseaddr(&self, reuse: bool) -> Result<()> {
        use std::os::unix::io::{FromRawFd, IntoRawFd};

        let fd = self.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(fd) };
        let result = socket.set_reuse_address(reuse).map_err(Error::from);
        let _ = socket.into_raw_fd();
        result
    }

    #[cfg(target_os = "linux")]
    fn set_defer_accept(&self, timeout: Duration) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        const TCP_DEFER_ACCEPT: i32 = 9;

        let fd = self.as_raw_fd();
        let timeout_secs = timeout.as_secs() as i32;

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_DEFER_ACCEPT,
                &timeout_secs as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            Err(Error::Io(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    fn local_sockaddr(&self) -> Result<SockAddr> {
        let addr = self.local_addr().map_err(Error::from)?;
        Ok(SockAddr::from_std(addr))
    }
}

/// TCP connection builder with timeout support
pub struct TcpConnector {
    timeout: Option<Duration>,
    nodelay: bool,
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpConnector {
    /// Create a new TCP connector with default settings
    pub fn new() -> Self {
        TcpConnector {
            timeout: None,
            nodelay: true, // Default to TCP_NODELAY on
        }
    }

    /// Set connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set TCP_NODELAY option
    pub fn nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = nodelay;
        self
    }

    /// Connect to an address
    pub fn connect(&self, addr: &SockAddr) -> Result<TcpStream> {
        let std_addr = addr.to_std()
            .ok_or_else(|| Error::UnsupportedFamily("Cannot connect to Unix socket".to_string()))?;

        self.connect_std(&std_addr)
    }

    /// Connect to a standard library SocketAddr
    pub fn connect_std(&self, addr: &SocketAddr) -> Result<TcpStream> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(Error::from)?;

        // Set TCP_NODELAY
        socket.set_nodelay(self.nodelay).map_err(Error::from)?;

        // If we have a timeout, set non-blocking
        if let Some(timeout) = self.timeout {
            socket.set_nonblocking(true).map_err(Error::from)?;

            let addr = Socket2Addr::from(*addr);
            match socket.connect(&addr) {
                Ok(_) => {
                    // Connected immediately (unlikely)
                    socket.set_nonblocking(false).map_err(Error::from)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock ||
                         e.raw_os_error() == Some(libc::EINPROGRESS) => {
                    // Wait for connection with timeout
                    self.wait_for_connect(&socket, timeout)?;
                    socket.set_nonblocking(false).map_err(Error::from)?;
                }
                Err(e) => return Err(Error::from(e)),
            }
        } else {
            // Blocking connect
            let addr = Socket2Addr::from(*addr);
            socket.connect(&addr).map_err(Error::from)?;
        }

        // Convert socket2::Socket to std::net::TcpStream
        let stream: TcpStream = socket.into();
        Ok(stream)
    }

    /// Connect to an address string (with DNS resolution)
    pub fn connect_addr(&self, addr: &str, default_port: Option<&str>) -> Result<TcpStream> {
        let mut iter = ResolveIter::resolve(addr, default_port)?;

        let first_addr = iter.next()
            .ok_or_else(|| Error::ResolutionFailed("No addresses resolved".to_string()))?;

        // Try first address
        match self.connect(&first_addr) {
            Ok(stream) => Ok(stream),
            Err(first_err) => {
                // Try remaining addresses
                for addr in iter {
                    if let Ok(stream) = self.connect(&addr) {
                        return Ok(stream);
                    }
                }
                // All failed, return first error
                Err(first_err)
            }
        }
    }

    /// Wait for a non-blocking connect to complete
    fn wait_for_connect(&self, socket: &Socket, timeout: Duration) -> Result<()> {
        use libc::{poll, pollfd, POLLWRNORM};

        let fd = socket.as_raw_fd();
        let mut pfd = pollfd {
            fd,
            events: POLLWRNORM,
            revents: 0,
        };

        let timeout_ms = timeout.as_millis() as i32;
        let ret = unsafe { poll(&mut pfd, 1, timeout_ms) };

        if ret < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        if ret == 0 {
            return Err(Error::Timeout);
        }

        // Check if connection succeeded
        let err = socket.take_error().map_err(Error::from)?;
        if let Some(err) = err {
            return Err(Error::from(err));
        }

        Ok(())
    }
}

/// TCP listener builder
pub struct TcpListenerBuilder {
    reuseaddr: bool,
    backlog: i32,
    #[cfg(target_os = "linux")]
    defer_accept: Option<Duration>,
}

impl Default for TcpListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpListenerBuilder {
    /// Create a new TCP listener builder with default settings
    pub fn new() -> Self {
        TcpListenerBuilder {
            reuseaddr: true,
            backlog: 128,
            #[cfg(target_os = "linux")]
            defer_accept: None,
        }
    }

    /// Set SO_REUSEADDR option (default: true)
    pub fn reuseaddr(mut self, reuse: bool) -> Self {
        self.reuseaddr = reuse;
        self
    }

    /// Set listen backlog (default: 128)
    pub fn backlog(mut self, backlog: i32) -> Self {
        self.backlog = backlog;
        self
    }

    /// Set TCP_DEFER_ACCEPT option (Linux only)
    #[cfg(target_os = "linux")]
    pub fn defer_accept(mut self, timeout: Duration) -> Self {
        self.defer_accept = Some(timeout);
        self
    }

    /// Bind to an address
    pub fn bind(&self, addr: &SockAddr) -> Result<TcpListener> {
        let std_addr = addr.to_std()
            .ok_or_else(|| Error::UnsupportedFamily("Cannot bind Unix socket as TCP".to_string()))?;

        self.bind_std(&std_addr)
    }

    /// Bind to a standard library SocketAddr
    pub fn bind_std(&self, addr: &SocketAddr) -> Result<TcpListener> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(Error::from)?;

        // Set SO_REUSEADDR
        socket.set_reuse_address(self.reuseaddr).map_err(Error::from)?;

        // For IPv6, set IPV6_V6ONLY to avoid conflicts with IPv4
        if matches!(addr, SocketAddr::V6(_)) {
            socket.set_only_v6(true).map_err(Error::from)?;
        }

        // Bind
        let addr = Socket2Addr::from(*addr);
        socket.bind(&addr).map_err(Error::from)?;

        // Listen
        socket.listen(self.backlog).map_err(Error::from)?;

        // Convert to TcpListener
        let listener: TcpListener = socket.into();

        // Set TCP_DEFER_ACCEPT if configured (Linux only)
        #[cfg(target_os = "linux")]
        if let Some(timeout) = self.defer_accept {
            listener.set_defer_accept(timeout)?;
        }

        Ok(listener)
    }

    /// Bind to an address string (with DNS resolution)
    pub fn bind_addr(&self, addr: &str, default_port: Option<&str>) -> Result<TcpListener> {
        let resolved = ResolveIter::resolve_first(addr, default_port)?;
        self.bind(&resolved)
    }
}

/// Check if an I/O error is acceptable for TCP operations
///
/// Some errors are expected in normal TCP operations (like connection reset)
/// and should not cause panics or unexpected failures.
pub fn is_acceptable_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
    ) || matches!(
        err.raw_os_error(),
        Some(libc::ECONNRESET)
            | Some(libc::ENOTCONN)
            | Some(libc::EPIPE)
            | Some(libc::EAGAIN)
            | Some(libc::ETIMEDOUT)
            | Some(libc::ENETDOWN)
            | Some(libc::ENETUNREACH)
            | Some(libc::ENETRESET)
            | Some(libc::ECONNABORTED)
            | Some(libc::EHOSTUNREACH)
            | Some(libc::EHOSTDOWN)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_connect_timeout() {
        let connector = TcpConnector::new().timeout(Duration::from_millis(100));

        // Try to connect to a non-routable address (should timeout)
        let result = connector.connect_addr("192.0.2.1:80", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_listener_bind() {
        let builder = TcpListenerBuilder::new();
        let listener = builder.bind_addr("127.0.0.1:0", None).unwrap();

        let addr = listener.local_sockaddr().unwrap();
        assert!(addr.is_ipv4());
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_tcp_connect_and_accept() {
        let builder = TcpListenerBuilder::new();
        let listener = builder.bind_addr("127.0.0.1:0", None).unwrap();
        let listen_addr = listener.local_addr().unwrap();

        // Spawn a thread to accept connection
        let handle = std::thread::spawn(move || {
            listener.accept().unwrap()
        });

        // Connect
        let connector = TcpConnector::new().timeout(Duration::from_secs(5));
        let mut client = connector.connect_std(&listen_addr).unwrap();

        // Accept
        let (mut server, _) = handle.join().unwrap();

        // Test communication
        client.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_tcp_nodelay() {
        let connector = TcpConnector::new().nodelay(true);
        let builder = TcpListenerBuilder::new();
        let listener = builder.bind_addr("127.0.0.1:0", None).unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let stream = connector.connect_std(&listen_addr).unwrap();
        // TCP_NODELAY should be set
        assert!(stream.nodelay().unwrap());
    }

    #[test]
    fn test_tcp_check_hup() {
        let builder = TcpListenerBuilder::new();
        let listener = builder.bind_addr("127.0.0.1:0", None).unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let connector = TcpConnector::new();
        let client = connector.connect_std(&listen_addr).unwrap();

        // Should not be in HUP state when connected
        assert!(!client.check_hup().unwrap());
    }
}
