// tests/unit/validation_tests.rs
use crate::common;
use mesh_network::error::MeshError;
use mesh_network::packet::{PacketType, UntrustedPacket};
use mesh_network::validate::ValidationRules;

use std::time::{Duration, SystemTime};

#[test]
fn test_nonce_replay_prevention() {
    let rules = ValidationRules::new();
    let key_pair = common::create_test_keypair();

    // Create first packet
    let packet1 = common::create_test_packet_bytes(b"test", &key_pair);
    let untrusted1 = UntrustedPacket::from_bytes(&packet1).unwrap();

    // First use should succeed
    assert!(rules.validate_packet(&untrusted1).is_ok());

    // Same nonce should fail
    assert!(matches!(
        rules.validate_packet(&untrusted1),
        Err(MeshError::ValidationError(_))
    ));
}

#[test]
fn test_packet_age_validation() {
    let rules = ValidationRules::new();
    let key_pair = common::create_test_keypair();

    // Create packet with old timestamp
    let mut old_header = common::create_test_header();
    old_header.nonce = (SystemTime::now() - Duration::from_secs(120))
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_be_bytes();

    let packet = common::create_test_packet_with_header(old_header, b"test", &key_pair);
    let untrusted = UntrustedPacket::from_bytes(&packet).unwrap();

    // Old packet should be rejected
    assert!(matches!(
        rules.validate_packet(&untrusted),
        Err(MeshError::ValidationError(_))
    ));
}

#[test]
fn test_size_limits() {
    let mut rules = ValidationRules::new();
    let key_pair = common::create_test_keypair();

    // Test different packet types with various sizes
    for (packet_type, size) in &[
        (PacketType::Data, 1024 * 65), // Too large
        (PacketType::Control, 2048),   // Too large
        (PacketType::Discovery, 256),  // OK
        (PacketType::Error, 512),      // OK
    ] {
        let payload = vec![0u8; *size];
        let mut header = common::create_test_header();
        header.packet_type = *packet_type as u8;

        let packet = common::create_test_packet_with_header(header, &payload, &key_pair);
        let untrusted = UntrustedPacket::from_bytes(&packet).unwrap();

        let result = rules.validate_packet(&untrusted);
        match size {
            s if s > rules.get_size_limit(packet_type).unwrap() => {
                assert!(result.is_err());
            }
            _ => {
                assert!(result.is_ok());
            }
        }
    }
}
