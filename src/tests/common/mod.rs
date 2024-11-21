// tests/common/mod.rs
use mesh_network::packet::{PacketHeader, PACKET_MAGIC};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

/// Create a keypair for testing
pub fn create_test_keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap()
}

/// Create a default test header
pub fn create_test_header() -> PacketHeader {
    PacketHeader {
        magic: PACKET_MAGIC,
        version: 1,
        packet_type: 0,
        payload_length: 0,
        source_id: [0; 32],
        destination_id: [1; 32],
        nonce: [0; 8],
    }
}

/// Create a complete packet with signature
pub fn create_test_packet_bytes(payload: &[u8], key_pair: &Ed25519KeyPair) -> Vec<u8> {
    let mut header = create_test_header();
    header.payload_length = payload.len() as u16;

    // Create message to sign
    let mut message = Vec::new();
    message.extend_from_slice(header.as_bytes());
    message.extend_from_slice(payload);

    // Sign the message
    let signature = key_pair.sign(&message);

    // Build complete packet
    let mut packet_data = Vec::new();
    packet_data.extend_from_slice(header.as_bytes());
    packet_data.extend_from_slice(payload);
    packet_data.extend_from_slice(signature.as_ref());

    packet_data
}

/// Create test peer IDs
pub fn create_test_peer_id(index: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = index;
    id
}
