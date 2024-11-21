// tests/unit/packet_tests.rs
use crate::common;
use mesh_network::{
    error::MeshError,
    packet::{PacketHeader, PacketType, UntrustedPacket, PACKET_MAGIC},
};

/// Just like HTTP methods (GET, POST, etc.), we test our packet types
#[test]
fn test_packet_types() {
    // Similar to validating HTTP methods, we ensure only valid packet types are accepted
    assert_eq!(PacketType::try_from(0).unwrap(), PacketType::Data); // Like HTTP POST
    assert_eq!(PacketType::try_from(1).unwrap(), PacketType::Control); // Like HTTP HEAD
    assert_eq!(PacketType::try_from(2).unwrap(), PacketType::Discovery); // Like HTTP OPTIONS
    assert_eq!(PacketType::try_from(255).unwrap(), PacketType::Error); // Like HTTP 500

    // Like trying an invalid HTTP method
    assert!(PacketType::try_from(3).is_err());
}

/// Similar to validating HTTP headers before processing a request
#[test]
fn test_header_validation() {
    // Like checking if "Content-Type" header is valid
    let valid_header = common::create_test_header();
    assert!(valid_header.validate().is_ok());

    // Like receiving a request with invalid "Authorization" header
    let invalid_magic = PacketHeader {
        magic: [0, 0, 0, 0], // Like an invalid API key
        ..valid_header
    };
    assert!(invalid_magic.validate().is_err());

    // Like receiving a request with unsupported API version
    let invalid_version = PacketHeader {
        version: 2, // Like receiving "application/json; v2" when we only support v1
        ..valid_header
    };
    assert!(invalid_version.validate().is_err());
}

/// Tests realistic message scenarios, like different API payloads
#[test]
fn test_realistic_messages() {
    let key_pair = common::create_test_keypair();

    // Test JSON-like message
    let json_message = b"{\"type\":\"status\",\"status\":\"online\"}";
    let packet = create_and_verify_packet(json_message, &key_pair);
    assert_eq!(packet.payload(), json_message);

    // Test binary data (like file upload)
    let binary_data = vec![0xFF; 512]; // Simulating binary file data
    let packet = create_and_verify_packet(&binary_data, &key_pair);
    assert_eq!(packet.payload(), binary_data);

    // Test UTF-8 message (like chat message)
    let utf8_message = "Hello, 世界!".as_bytes();
    let packet = create_and_verify_packet(utf8_message, &key_pair);
    assert_eq!(packet.payload(), utf8_message);
}

/// Like testing HTTP request validation
#[test]
fn test_malformed_packets() {
    // Empty request body
    assert!(matches!(
        UntrustedPacket::from_bytes(&[]),
        Err(MeshError::PacketError(_))
    ));

    // Like receiving truncated HTTP headers
    let small_packet = vec![0u8; 10];
    assert!(matches!(
        UntrustedPacket::from_bytes(&small_packet),
        Err(MeshError::PacketError(_))
    ));

    // Like missing authentication token
    let key_pair = common::create_test_keypair();
    let mut packet_bytes = common::create_test_packet_bytes(b"test", &key_pair);
    packet_bytes.truncate(packet_bytes.len() - 64); // Remove signature (like removing JWT token)
    assert!(matches!(
        UntrustedPacket::from_bytes(&packet_bytes),
        Err(MeshError::PacketError(_))
    ));
}

/// Tests different payload sizes (like different HTTP body sizes)
#[test]
fn test_payload_sizes() {
    let key_pair = common::create_test_keypair();

    // Like empty POST request
    verify_payload_size(&key_pair, b"", "empty payload");

    // Like typical JSON payload
    verify_payload_size(&key_pair, b"{\"status\":\"ok\"}", "small JSON");

    // Like file upload
    let large_data = vec![0u8; 1024 * 64]; // 64KB like a small image
    verify_payload_size(&key_pair, &large_data, "large payload");
}

/// Tests packet integrity (like ensuring complete HTTP request)
#[test]
fn test_packet_integrity() {
    let key_pair = common::create_test_keypair();

    // Create packet with metadata (like HTTP headers) and payload (like HTTP body)
    let metadata = "user_id=123";
    let content = "Hello, World!";
    let combined = [metadata, content].join("|").into_bytes();

    let packet_bytes = common::create_test_packet_bytes(&combined, &key_pair);
    let packet = UntrustedPacket::from_bytes(&packet_bytes).unwrap();

    // Verify packet structure (like validating complete HTTP request)
    assert_eq!(packet.header().magic, PACKET_MAGIC); // Like checking "HTTP/1.1"
    assert_eq!(packet.header().version, 1); // Like API version
    assert_eq!(packet.header().packet_type, 0); // Like request method
    assert_eq!(packet.payload().len(), combined.len()); // Like Content-Length
    assert_eq!(packet.signature().len(), 64); // Like JWT signature
}

// Helper function to create and verify a packet
fn create_and_verify_packet(
    payload: &[u8],
    key_pair: &ring::signature::Ed25519KeyPair,
) -> UntrustedPacket {
    let packet_bytes = common::create_test_packet_bytes(payload, key_pair);
    UntrustedPacket::from_bytes(&packet_bytes).unwrap()
}

// Helper function to verify payload handling
fn verify_payload_size(
    key_pair: &ring::signature::Ed25519KeyPair,
    payload: &[u8],
    test_name: &str,
) {
    let packet_bytes = common::create_test_packet_bytes(payload, key_pair);
    let packet = UntrustedPacket::from_bytes(&packet_bytes).unwrap();
    assert_eq!(
        packet.payload().len(),
        payload.len(),
        "{} size mismatch",
        test_name
    );
}
