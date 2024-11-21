// tests/unit/packet_tests.rs
use crate::common;
use mesh_network::error::MeshError;
use mesh_network::packet::{PacketHeader, PacketType, UntrustedPacket, PACKET_MAGIC};

#[test]
fn test_packet_type_conversion() {
    // Original test moved from packet.rs
    assert_eq!(PacketType::try_from(0).unwrap(), PacketType::Data);
    assert_eq!(PacketType::try_from(1).unwrap(), PacketType::Control);
    assert_eq!(PacketType::try_from(2).unwrap(), PacketType::Discovery);
    assert_eq!(PacketType::try_from(255).unwrap(), PacketType::Error);
    assert!(PacketType::try_from(3).is_err());
}

#[test]
fn test_header_validation() {
    // Original test moved from packet.rs
    let valid_header = common::create_test_header();
    assert!(valid_header.validate().is_ok());

    let invalid_magic = PacketHeader {
        magic: [0, 0, 0, 0],
        ..valid_header
    };
    assert!(invalid_magic.validate().is_err());

    let invalid_version = PacketHeader {
        version: 2,
        ..valid_header
    };
    assert!(invalid_version.validate().is_err());
}

#[test]
fn test_packet_creation() {
    let key_pair = common::create_test_keypair();
    let payload = b"Test payload";
    let packet_bytes = common::create_test_packet_bytes(payload, &key_pair);

    match UntrustedPacket::from_bytes(&packet_bytes) {
        Ok(packet) => {
            assert_eq!(packet.header().magic, PACKET_MAGIC);
            assert_eq!(packet.header().payload_length as usize, payload.len());
            assert_eq!(packet.payload(), payload);
        }
        Err(e) => panic!("Failed to create packet: {}", e),
    }
}

#[test]
fn test_invalid_packet_sizes() {
    // Test empty packet
    assert!(matches!(
        UntrustedPacket::from_bytes(&[]),
        Err(MeshError::PacketError(_))
    ));

    // Test packet too small for header
    let small_packet = vec![0u8; 10];
    assert!(matches!(
        UntrustedPacket::from_bytes(&small_packet),
        Err(MeshError::PacketError(_))
    ));

    // Test packet missing signature
    let key_pair = common::create_test_keypair();
    let mut packet_bytes = common::create_test_packet_bytes(b"test", &key_pair);
    packet_bytes.truncate(packet_bytes.len() - 64); // Remove signature
    assert!(matches!(
        UntrustedPacket::from_bytes(&packet_bytes),
        Err(MeshError::PacketError(_))
    ));
}

#[test]
fn test_payload_handling() {
    let key_pair = common::create_test_keypair();

    // Test empty payload
    let empty_packet = common::create_test_packet_bytes(b"", &key_pair);
    let packet = UntrustedPacket::from_bytes(&empty_packet).unwrap();
    assert_eq!(packet.payload().len(), 0);

    // Test max size payload (assuming max size is 65535 due to u16 length)
    let large_payload = vec![0u8; 1024]; // Using 1KB for test
    let large_packet = common::create_test_packet_bytes(&large_payload, &key_pair);
    let packet = UntrustedPacket::from_bytes(&large_packet).unwrap();
    assert_eq!(packet.payload().len(), large_payload.len());
}

#[test]
fn test_packet_field_consistency() {
    let key_pair = common::create_test_keypair();
    let payload = b"Test";
    let packet_bytes = common::create_test_packet_bytes(payload, &key_pair);
    let packet = UntrustedPacket::from_bytes(&packet_bytes).unwrap();

    // Verify all fields are as expected
    assert_eq!(packet.header().magic, PACKET_MAGIC);
    assert_eq!(packet.header().version, 1);
    assert_eq!(packet.header().packet_type, 0);
    assert_eq!(packet.header().payload_length as usize, payload.len());
    assert_eq!(packet.payload().len(), payload.len());
    assert_eq!(packet.signature().len(), 64); // Ed25519 signatures are 64 bytes
}
