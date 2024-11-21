// examples/packet_validation.rs
use mesh_network::{
    packet::{PacketHeader, UntrustedPacket, PACKET_MAGIC},
    state::ValidationState,
};
use ring::signature::Ed25519KeyPair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a test key pair
    let rng = ring::rand::SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref())?;

    // Create a test packet
    let mut packet_data = Vec::new();

    // Add header
    let header = PacketHeader {
        magic: PACKET_MAGIC,
        version: 1,
        packet_type: 0, // Data packet
        payload_length: 5,
        source_id: [1; 32],
        nonce: [0; 8],
    };

    // Create message to sign
    let mut message = Vec::new();
    message.extend_from_slice(header.as_bytes());
    message.extend_from_slice(b"Hello"); // Payload

    // Sign the message
    let signature = key_pair.sign(&message);

    // Construct complete packet
    packet_data.extend_from_slice(header.as_bytes());
    packet_data.extend_from_slice(b"Hello"); // Payload
    packet_data.extend_from_slice(signature.as_ref());

    // Try to parse and validate
    match UntrustedPacket::from_bytes(&packet_data) {
        Ok(packet) => {
            println!("Parsed packet successfully!");

            // Validate the packet
            match ValidationState::validate_packet(packet, key_pair.public_key().as_ref()) {
                ValidationState::Complete(trusted_packet) => {
                    println!("Validation successful!");
                    println!(
                        "Packet payload: {:?}",
                        String::from_utf8_lossy(trusted_packet.payload())
                    );
                    println!("Validated at: {:?}", trusted_packet.validated_at());
                }
                ValidationState::Invalid(e) => {
                    println!("Validation failed: {}", e);
                }
                _ => println!("Validation incomplete"),
            }
        }
        Err(e) => {
            println!("Failed to parse packet: {}", e);
        }
    }

    Ok(())
}
