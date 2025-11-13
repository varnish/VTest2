//! Integration tests for network utilities
//!
//! These tests verify that the network layer works correctly in realistic scenarios.

use std::io::{Read, Write};
use std::time::Duration;
use vtest2::net::{ResolveIter, TcpConnector, TcpListenerBuilder, TcpExt, TcpListenerExt};

#[test]
fn test_full_client_server_flow() {
    // Create a listener on a random port
    let listener = TcpListenerBuilder::new()
        .backlog(10)
        .bind_addr("127.0.0.1:0", None)
        .expect("Failed to bind listener");

    let listen_addr = listener.local_addr().expect("Failed to get local address");
    println!("Server listening on {}", listen_addr);

    // Spawn a server thread
    let server_handle = std::thread::spawn(move || {
        let (mut stream, client_addr) = listener.accept().expect("Failed to accept connection");
        println!("Server accepted connection from {}", client_addr);

        // Read a message
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).expect("Failed to read from client");
        let message = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(message, "Hello from client");

        // Send a response
        stream.write_all(b"Hello from server").expect("Failed to write to client");
    });

    // Give the server time to start
    std::thread::sleep(Duration::from_millis(50));

    // Connect as a client
    let connector = TcpConnector::new()
        .timeout(Duration::from_secs(5))
        .nodelay(true);

    let mut client = connector.connect_std(&listen_addr).expect("Failed to connect");
    println!("Client connected");

    // Send a message
    client.write_all(b"Hello from client").expect("Failed to write to server");

    // Read response
    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).expect("Failed to read from server");
    let response = String::from_utf8_lossy(&buf[..n]);
    assert_eq!(response, "Hello from server");

    // Wait for server to finish
    server_handle.join().expect("Server thread panicked");
}

#[test]
fn test_multiple_connections() {
    let listener = TcpListenerBuilder::new()
        .bind_addr("127.0.0.1:0", None)
        .expect("Failed to bind listener");

    let listen_addr = listener.local_addr().expect("Failed to get local address");

    let server_handle = std::thread::spawn(move || {
        for i in 0..5 {
            let (mut stream, _) = listener.accept().expect("Failed to accept connection");
            let mut buf = [0u8; 10];
            let n = stream.read(&mut buf).expect("Failed to read");
            stream.write_all(&buf[..n]).expect("Failed to write");
            println!("Server handled connection {}", i);
        }
    });

    std::thread::sleep(Duration::from_millis(50));

    // Create multiple client connections
    let mut handles = vec![];
    for i in 0..5 {
        let addr = listen_addr;
        let handle = std::thread::spawn(move || {
            let connector = TcpConnector::new().timeout(Duration::from_secs(5));
            let mut client = connector.connect_std(&addr).expect("Failed to connect");

            let message = format!("Client-{}", i);
            client.write_all(message.as_bytes()).expect("Failed to write");

            let mut buf = [0u8; 10];
            let n = client.read(&mut buf).expect("Failed to read");
            let response = String::from_utf8_lossy(&buf[..n]);
            assert_eq!(response, message);
        });
        handles.push(handle);
    }

    // Wait for all clients to finish
    for handle in handles {
        handle.join().expect("Client thread panicked");
    }

    server_handle.join().expect("Server thread panicked");
}

#[test]
fn test_connection_timeout() {
    let connector = TcpConnector::new().timeout(Duration::from_millis(100));

    // Try to connect to a non-routable address (should timeout)
    let result = connector.connect_addr("192.0.2.1:80", None);
    assert!(result.is_err());
}

#[test]
fn test_address_resolution() {
    // Test resolving localhost
    let addrs: Vec<_> = ResolveIter::resolve("localhost:8080", None)
        .expect("Failed to resolve localhost")
        .collect();

    assert!(!addrs.is_empty());
    for addr in &addrs {
        assert_eq!(addr.port(), 8080);
    }

    // Test resolving IPv4 address
    let addr = ResolveIter::resolve_first("127.0.0.1:9090", None)
        .expect("Failed to resolve IPv4");
    assert!(addr.is_ipv4());
    assert_eq!(addr.port(), 9090);
}

#[test]
fn test_port_range_resolution() {
    let addrs: Vec<_> = ResolveIter::resolve("127.0.0.1:8000-8002", None)
        .expect("Failed to resolve port range")
        .collect();

    // Should have 3 addresses (one for each port)
    assert!(addrs.len() >= 3);

    // Check that we have different ports
    let ports: std::collections::HashSet<_> = addrs.iter().map(|a| a.port()).collect();
    assert!(ports.contains(&8000));
    assert!(ports.contains(&8001));
    assert!(ports.contains(&8002));
}

#[test]
fn test_socket_options() {
    let listener = TcpListenerBuilder::new()
        .reuseaddr(true)
        .bind_addr("127.0.0.1:0", None)
        .expect("Failed to bind listener");

    let listen_addr = listener.local_addr().expect("Failed to get local address");

    let connector = TcpConnector::new()
        .nodelay(true)
        .timeout(Duration::from_secs(5));

    let stream = connector.connect_std(&listen_addr).expect("Failed to connect");

    // Verify TCP_NODELAY is set
    assert!(stream.nodelay().expect("Failed to get nodelay"));

    // Test setting various options
    stream.set_nodelay(false).expect("Failed to set nodelay");
    assert!(!stream.nodelay().expect("Failed to get nodelay"));

    stream.set_keepalive(true).expect("Failed to set keepalive");

    stream.set_linger(Some(Duration::from_secs(1))).expect("Failed to set linger");

    stream.set_read_timeout_dur(Some(Duration::from_secs(5)))
        .expect("Failed to set read timeout");
}

#[test]
fn test_read_with_timeout() {
    let listener = TcpListenerBuilder::new()
        .bind_addr("127.0.0.1:0", None)
        .expect("Failed to bind listener");

    let listen_addr = listener.local_addr().expect("Failed to get local address");

    let _server_handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("Failed to accept");
        // Don't send anything, just hold the connection open
        std::thread::sleep(Duration::from_secs(2));
        drop(stream);
    });

    std::thread::sleep(Duration::from_millis(50));

    let connector = TcpConnector::new().timeout(Duration::from_secs(5));
    let mut client = connector.connect_std(&listen_addr).expect("Failed to connect");

    // Try to read with a short timeout (should timeout)
    let mut buf = [0u8; 1024];
    let result = client.read_with_timeout(&mut buf, Some(Duration::from_millis(100)));
    assert!(result.is_err());
}

#[test]
fn test_sockaddr_operations() {
    let listener = TcpListenerBuilder::new()
        .bind_addr("127.0.0.1:0", None)
        .expect("Failed to bind listener");

    let listen_addr = listener.local_sockaddr().expect("Failed to get local sockaddr");
    assert!(listen_addr.is_ipv4());
    assert!(listen_addr.port() > 0);

    let connector = TcpConnector::new().timeout(Duration::from_secs(5));
    let stream = connector.connect(&listen_addr).expect("Failed to connect");

    let local_addr = stream.local_sockaddr().expect("Failed to get local address");
    let peer_addr = stream.peer_sockaddr().expect("Failed to get peer address");

    assert!(local_addr.is_ipv4());
    assert!(peer_addr.is_ipv4());
    assert_eq!(peer_addr.port(), listen_addr.port());
}

#[test]
fn test_ipv6_connection() {
    // Try to bind to IPv6 localhost
    let result = TcpListenerBuilder::new().bind_addr("[::1]:0", None);

    // This test may fail on systems without IPv6 support
    if let Ok(listener) = result {
        let listen_addr = listener.local_addr().expect("Failed to get local address");
        assert!(listen_addr.is_ipv6());

        let connector = TcpConnector::new().timeout(Duration::from_secs(5));
        let stream = connector.connect_std(&listen_addr).expect("Failed to connect IPv6");

        let peer_addr = stream.peer_sockaddr().expect("Failed to get peer address");
        assert!(peer_addr.is_ipv6());
    } else {
        println!("Skipping IPv6 test - IPv6 not available");
    }
}
