// tests/unit/network_tests.rs
use crate::common;
use mesh_network::error::MeshError;
use mesh_network::network::{ForwardingMetadata, NetworkConfig, NetworkManager};
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

#[test]
fn test_rate_limiting() {
    let key_pair = common::create_test_keypair();
    let config = NetworkConfig {
        rate_limit: 2, // Only allow 2 packets per second
        ..NetworkConfig::default()
    };
    let mut network = NetworkManager::new(key_pair.clone(), config);

    // Add a peer
    let peer_key = key_pair.public_key().as_ref().to_vec();
    network.add_peer(&peer_key).unwrap();

    // Create test packet
    let packet_bytes = common::create_test_packet_bytes(b"test", &key_pair);
    let packet = UntrustedPacket::from_bytes(&packet_bytes).unwrap();

    // First two packets should succeed
    assert!(network.handle_packet(packet.clone()).is_ok());
    assert!(network.handle_packet(packet.clone()).is_ok());

    // Third packet should be rate limited
    assert!(matches!(
        network.handle_packet(packet),
        Err(MeshError::NetworkError(_))
    ));
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
