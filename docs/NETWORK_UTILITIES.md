# Network Utilities - Rust Implementation

This document describes the Rust implementation of VTest2's network utilities layer, ported from the C modules `vtcp.c`, `vsa.c`, and `vss.c` from Varnish Cache.

## Overview

The network utilities provide idiomatic Rust interfaces for:
- **Socket address handling** - Type-safe wrappers for IPv4, IPv6, and Unix domain socket addresses
- **DNS resolution** - Flexible address parsing and name resolution
- **TCP operations** - Connection management with timeout support and socket options

## Module Structure

```
src/net/
├── mod.rs       - Public API and error types
├── addr.rs      - Socket address handling (vsa.c equivalent)
├── resolver.rs  - DNS resolution and parsing (vss.c equivalent)
└── tcp.rs       - TCP utilities (vtcp.c equivalent)
```

## API Documentation

### Socket Addresses (`SockAddr`)

The `SockAddr` enum provides type-safe handling of different address families:

```rust
use vtest2::net::SockAddr;
use std::net::Ipv4Addr;

// Create IPv4 address
let addr = SockAddr::new_v4(Ipv4Addr::new(127, 0, 0, 1), 8080);

// Get port and IP
assert_eq!(addr.port(), 8080);
assert_eq!(addr.addr_string(), "127.0.0.1");

// Compare addresses (IP only, ignoring ports)
let addr2 = SockAddr::new_v4(Ipv4Addr::new(127, 0, 0, 1), 9090);
assert!(addr.compare_ip(&addr2));
```

### DNS Resolution

The `ResolveIter` provides DNS resolution with support for multiple address formats:

**Supported formats:**
- `"localhost"` `"localhost:80"` `"localhost 80"`
- `"127.0.0.1"` `"127.0.0.1:80"` `"127.0.0.1 80"`
- `"[::1]"` `"[::1]:80"` `"[::1] 80"`
- `"localhost:8000-8010"` (port ranges)

```rust
use vtest2::net::ResolveIter;

// Resolve and iterate through addresses
let addrs: Vec<_> = ResolveIter::resolve("localhost:8080", None)
    .expect("Resolution failed")
    .collect();

// Get first address only
let addr = ResolveIter::resolve_first("127.0.0.1:9090", None)
    .expect("Resolution failed");

// Port ranges
let addrs: Vec<_> = ResolveIter::resolve("127.0.0.1:8000-8005", None)
    .expect("Resolution failed")
    .collect();
// Returns addresses for ports 8000, 8001, 8002, 8003, 8004, 8005
```

### TCP Connection

The `TcpConnector` builder provides connection management with timeout support:

```rust
use vtest2::net::{TcpConnector, TcpExt};
use std::time::Duration;

// Create connector with timeout
let connector = TcpConnector::new()
    .timeout(Duration::from_secs(5))
    .nodelay(true);

// Connect to an address
let stream = connector.connect_addr("localhost:8080", None)
    .expect("Connection failed");

// Set socket options
stream.set_keepalive(true).unwrap();
stream.set_linger(Some(Duration::from_secs(1))).unwrap();

// Read with timeout
let mut buf = [0u8; 1024];
let n = stream.read_with_timeout(&mut buf, Some(Duration::from_millis(500)))
    .expect("Read failed");
```

### TCP Listener

The `TcpListenerBuilder` provides server socket creation:

```rust
use vtest2::net::{TcpListenerBuilder, TcpListenerExt};

// Create listener
let listener = TcpListenerBuilder::new()
    .reuseaddr(true)
    .backlog(128)
    .bind_addr("127.0.0.1:8080", None)
    .expect("Bind failed");

// Accept connections
let (stream, addr) = listener.accept().expect("Accept failed");

// Get local address as SockAddr
let local_addr = listener.local_sockaddr().unwrap();
```

### Socket Options

Both `TcpStream` and `TcpListener` have extension traits providing additional functionality:

**TcpExt (for TcpStream):**
- `set_nodelay()` - Set TCP_NODELAY
- `set_blocking()` - Set blocking/non-blocking mode
- `set_linger()` - Set SO_LINGER
- `set_keepalive()` - Set SO_KEEPALIVE
- `set_read_timeout_dur()` - Set read timeout
- `set_write_timeout_dur()` - Set write timeout
- `local_sockaddr()` - Get local address as SockAddr
- `peer_sockaddr()` - Get peer address as SockAddr
- `check_hup()` - Check if peer closed connection
- `read_with_timeout()` - Read with explicit timeout

**TcpListenerExt (for TcpListener):**
- `set_reuseaddr()` - Set SO_REUSEADDR
- `set_defer_accept()` - Set TCP_DEFER_ACCEPT (Linux only)
- `local_sockaddr()` - Get local address as SockAddr

## Error Handling

All operations return `Result<T, vtest2::net::Error>`:

```rust
pub enum Error {
    Io(std::io::Error),
    InvalidAddress(String),
    ResolutionFailed(String),
    Timeout,
    InvalidPortRange(String),
    UnsupportedFamily(String),
}
```

## Comparison with C Implementation

| C Module | Rust Module | Notes |
|----------|-------------|-------|
| `vsa.c` | `addr.rs` | Type-safe enum instead of opaque struct |
| `vss.c` | `resolver.rs` | Iterator-based API instead of callbacks |
| `vtcp.c` | `tcp.rs` | Builder pattern, extension traits |

### Key Differences

1. **Type Safety**: Rust's type system prevents many errors that C code must check at runtime
2. **Memory Safety**: No manual memory management, RAII handles cleanup
3. **Error Handling**: Result types instead of error codes and output parameters
4. **Iterators**: DNS resolution returns iterators instead of callbacks
5. **Builders**: Connection and listener creation use builder patterns
6. **Extension Traits**: Socket operations are provided via traits for better organization

## Testing

The implementation includes:
- **63 unit tests** covering all core functionality
- **9 integration tests** for realistic client-server scenarios
- Tests for IPv4, IPv6, address parsing, DNS resolution, timeouts, and socket options

Run tests with:
```bash
cargo test --lib --tests
```

## Platform Support

- **Primary**: Linux (all features)
- **macOS**: Supported (TCP_DEFER_ACCEPT not available)
- **BSD**: Should work (not extensively tested)

## Dependencies

- `socket2` - Low-level socket control
- `libc` - System call bindings
- `thiserror` - Error type derivation

## Future Enhancements

Potential improvements for future versions:
- Async/await support (Tokio integration)
- Unix domain socket support (currently prepared but not fully implemented)
- TCP Fast Open support
- More socket options (TCP_CORK, TCP_QUICKACK, etc.)
- SCTP support (if needed)

## Performance Notes

- Connection timeout uses `poll()` for efficiency
- TCP_NODELAY is enabled by default (can be disabled)
- SO_REUSEADDR is enabled by default for listeners
- Non-blocking I/O during connection establishment with timeout

## Examples

See `tests/network_integration_tests.rs` for comprehensive examples of:
- Client-server communication
- Multiple concurrent connections
- Timeout handling
- Socket option configuration
- Address resolution with port ranges
