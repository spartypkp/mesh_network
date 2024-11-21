// tests/unit/network_tests.rs
use crate::common;
use mesh_network::{
    error::MeshError,
    network::{ForwardingMetadata, NetworkConfig, NetworkManager},
    packet::{TrustedPacket, UntrustedPacket},
};
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_peer_management() {
    // Original test moved from network.rs
    let key_pair = common::create_test_keypair();
    let mut network = NetworkManager::new(key_pair, NetworkConfig::default());

    let peer_key = vec![1u8; 32];
    assert!(network.add_peer(&peer_key).is_ok());
    assert!(network.is_trusted_peer(&peer_key));

    network.remove_peer(&peer_key);
    assert!(!network.is_trusted_peer(&peer_key));
}

#[test]
fn test_peer_limit() {
    let key_pair = common::create_test_keypair();
    let config = NetworkConfig {
        max_peers: 2,
        ..NetworkConfig::default()
    };
    let mut network = NetworkManager::new(key_pair, config);

    // Add peers up to limit
    assert!(network.add_peer(&[1u8; 32]).is_ok());
    assert!(network.add_peer(&[2u8; 32]).is_ok());

    // Try to add one more peer
    assert!(matches!(
        network.add_peer(&[3u8; 32]),
        Err(MeshError::NetworkError(_))
    ));
}

/// Tests network behavior under high packet loss conditions
/// Important for mesh networks in unreliable environments
#[test]
fn test_packet_retry() {
    let (mut network, signing_key_pair) = setup_test_network(5);

    // Simulate packet loss by sending malformed packets
    let valid_packet = common::create_test_packet_bytes(b"valid", &signing_key_pair);
    let mut corrupted_packet = valid_packet.clone();

    // Let's try corrupting more of the packet
    corrupted_packet[0] = 0xFF; // Corrupt header
    corrupted_packet[1] = 0xFF; // Corrupt more header data

    println!("Valid packet: {:?}", &valid_packet[..10]);
    println!("Corrupted packet: {:?}", &corrupted_packet[..10]);

    // Valid packet should succeed
    let valid_result =
        UntrustedPacket::from_bytes(&valid_packet).expect("Valid packet should parse successfully");
    assert!(network.handle_packet(valid_result).is_ok());

    // Corrupted packet should fail gracefully
    let corrupted_result = UntrustedPacket::from_bytes(&corrupted_packet);
    println!("Corrupted packet result: {:?}", corrupted_result);

    assert!(
        matches!(corrupted_result, Err(MeshError::PacketError(_))),
        "Expected PacketError, got {:?}",
        corrupted_result
    );
}

/// Tests network behavior with multiple peer updates
/// Simulates dynamic mesh network topology changes
#[test]
fn test_peer_churn() {
    let key_pair = common::create_test_keypair();
    let mut network = NetworkManager::new(key_pair, NetworkConfig::default());

    let mut peers = Vec::new();

    // Add several peers
    for i in 0..5 {
        let peer_key = vec![i as u8; 32];
        network.add_peer(&peer_key).unwrap();
        peers.push(peer_key);
    }

    // Remove some peers
    network.remove_peer(&peers[1]);
    network.remove_peer(&peers[3]);

    // Add new peers
    let new_peer = vec![10u8; 32];
    network.add_peer(&new_peer).unwrap();

    // Verify network state
    assert!(network.is_trusted_peer(&peers[0]));
    assert!(!network.is_trusted_peer(&peers[1]));
    assert!(network.is_trusted_peer(&peers[2]));
    assert!(!network.is_trusted_peer(&peers[3]));
    assert!(network.is_trusted_peer(&peers[4]));
    assert!(network.is_trusted_peer(&new_peer));
}

/// Tests concurrent packet handling from multiple peers
/// Simulates busy mesh network with multiple active nodes
#[test]
fn test_multi_peer_traffic() {
    let (mut network, _) = setup_test_network(10);

    // Create multiple peer keypairs
    let peers: Vec<_> = (0..3)
        .map(|_| {
            let kp = common::create_test_keypair();
            let pub_key = kp.public_key().as_ref().to_vec();
            network.add_peer(&pub_key).unwrap();
            kp
        })
        .collect();

    // Simulate traffic from different peers
    for (i, peer) in peers.iter().enumerate() {
        let payload = format!("peer{}_message", i);
        assert!(handle_test_packet(&mut network, payload.as_bytes(), peer).is_ok());
    }
}

/// Tests network behavior under resource constraints
/// Important for embedded systems and IoT devices
#[test]
fn test_resource_limits() {
    let key_pair = common::create_test_keypair();
    let config = NetworkConfig {
        max_peers: 2,
        rate_limit: 5,
        peer_timeout: Duration::from_millis(100),
        ..NetworkConfig::default()
    };

    let mut network = NetworkManager::new(key_pair, config);

    // Test peer limit
    assert!(network.add_peer(&[1u8; 32]).is_ok());
    assert!(network.add_peer(&[2u8; 32]).is_ok());
    assert!(network.add_peer(&[3u8; 32]).is_err());

    // Test timeout cleanup
    sleep(Duration::from_millis(150));
    network.maintenance();

    // Should be able to add new peer after cleanup
    assert!(network.add_peer(&[4u8; 32]).is_ok());
}

/// Basic rate limiting test - similar to testing API endpoint limits
#[test]
fn test_basic_rate_limiting() {
    let (mut network, signing_key_pair) = setup_test_network(2); // Allow 2 requests/second

    // In web terms: Making 3 API calls in quick succession
    println!("\n=== Basic Rate Limiting Test ===");
    assert!(handle_test_packet(&mut network, b"request1", &signing_key_pair).is_ok());
    assert!(handle_test_packet(&mut network, b"request2", &signing_key_pair).is_ok());
    assert!(handle_test_packet(&mut network, b"request3", &signing_key_pair).is_err());
}

/// Tests rate limit reset after waiting
/// In a mesh network, this ensures nodes can resume sending after their limit resets,
/// just like how API rate limits reset after their time window
#[test]
fn test_rate_limit_reset() {
    let (mut network, signing_key_pair) = setup_test_network(2);

    // First window: Use up our rate limit
    assert!(handle_test_packet(&mut network, b"window1_req1", &signing_key_pair).is_ok());
    assert!(handle_test_packet(&mut network, b"window1_req2", &signing_key_pair).is_ok());
    assert!(handle_test_packet(&mut network, b"window1_req3", &signing_key_pair).is_err());

    // Wait for rate limit window to reset (like waiting for API limits to reset)
    println!("Waiting for rate limit window to reset...");
    sleep(Duration::from_secs(1));

    // New window: Should be able to send again
    assert!(handle_test_packet(&mut network, b"window2_req1", &signing_key_pair).is_ok());
}

/// Tests behavior under rapid message sending
/// Important for mesh networks to handle burst traffic, similar to
/// how web servers handle traffic spikes
#[test]
fn test_rapid_requests() {
    let (mut network, signing_key_pair) = setup_test_network(3);

    println!("\n=== Rapid Request Test ===");
    // Similar to load testing an API endpoint
    for i in 0..5 {
        let result = handle_test_packet(
            &mut network,
            format!("rapid{}", i).as_bytes(),
            &signing_key_pair,
        );
        println!("Request {}: {:?}", i, result);

        if i < 3 {
            assert!(result.is_ok(), "Request {} should succeed", i);
        } else {
            assert!(result.is_err(), "Request {} should be rate limited", i);
        }
    }
}

/// Tests sliding window behavior
/// Critical for mesh networks as it prevents message bursts at window boundaries
/// Similar to how modern API rate limiters use sliding windows instead of fixed windows
#[test]
fn test_sliding_window() {
    let (mut network, signing_key_pair) = setup_test_network(2);

    println!("\n=== Sliding Window Test ===");
    // First request
    assert!(handle_test_packet(&mut network, b"slide1", &signing_key_pair).is_ok());

    // Wait for half the window
    sleep(Duration::from_millis(600));
    assert!(handle_test_packet(&mut network, b"slide2", &signing_key_pair).is_ok());

    // Wait for just over half window - first request should have expired
    sleep(Duration::from_millis(600));
    assert!(
        handle_test_packet(&mut network, b"slide3", &signing_key_pair).is_ok(),
        "Should succeed as first request expired"
    );
}

/// Helper function to set up test network
fn setup_test_network(rate_limit: u32) -> (NetworkManager, Ed25519KeyPair) {
    let key_pair = common::create_test_keypair();
    let config = NetworkConfig {
        rate_limit,
        ..NetworkConfig::default()
    };

    let signing_key_pair = common::create_test_keypair();
    let public_key_bytes = signing_key_pair.public_key().as_ref().to_vec();
    let mut network = NetworkManager::new(key_pair, config);
    network.add_peer(&public_key_bytes).unwrap();

    (network, signing_key_pair)
}

/// Helper function to handle test packets
fn handle_test_packet(
    network: &mut NetworkManager,
    payload: &[u8],
    key_pair: &Ed25519KeyPair,
) -> Result<Option<TrustedPacket>, MeshError> {
    let packet_bytes = common::create_test_packet_bytes(payload, key_pair);
    network.handle_packet(UntrustedPacket::from_bytes(&packet_bytes).unwrap())
}

#[test]
fn test_network_maintenance() {
    let key_pair = common::create_test_keypair();
    let config = NetworkConfig {
        peer_timeout: Duration::from_secs(0), // Immediate timeout for testing
        ..NetworkConfig::default()
    };
    let mut network = NetworkManager::new(key_pair, config);

    // Add some peers
    network.add_peer(&[1u8; 32]).unwrap();
    network.add_peer(&[2u8; 32]).unwrap();

    // Run maintenance
    network.maintenance();

    // All peers should be removed due to timeout
    assert!(!network.is_trusted_peer(&[1u8; 32]));
    assert!(!network.is_trusted_peer(&[2u8; 32]));
}
