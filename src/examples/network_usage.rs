// examples/network_usage.rs
use mesh_network::{
    network::{NetworkConfig, NetworkManager},
    packet::{PacketHeader, UntrustedPacket, PACKET_MAGIC},
};
use ring::signature::Ed25519KeyPair;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a network configuration
    let config = NetworkConfig {
        max_peers: 10,
        peer_timeout: Duration::from_secs(60),
        max_hops: 3,
        rate_limit: 50,
    };

    // Generate a keypair for our node
    let rng = ring::rand::SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref())?;

    // Create the network manager
    let mut network = NetworkManager::new(key_pair.clone(), config);

    // Add a trusted peer
    let peer_key = key_pair.public_key().as_ref().to_vec();
    network.add_peer(&peer_key)?;

    // Create a test packet
    let mut packet_data = Vec::new();
    let header = PacketHeader {
        magic: PACKET_MAGIC,
        version: 1,
        packet_type: 0,
        payload_length: 5,
        source_id: [1; 32],
        destination_id: [2; 32],
        nonce: [0; 8],
    };

    // Create message to sign
    let mut message = Vec::new();
    message.extend_from_slice(header.as_bytes());
    message.extend_from_slice(b"Hello");

    // Sign the message
    let signature = key_pair.sign(&message);

    // Construct packet
    packet_data.extend_from_slice(header.as_bytes());
    packet_data.extend_from_slice(b"Hello");
    packet_data.extend_from_slice(signature.as_ref());

    // Parse and handle the packet
    if let Ok(packet) = UntrustedPacket::from_bytes(&packet_data) {
        match network.handle_packet(packet) {
            Ok(Some(trusted_packet)) => {
                println!("Successfully processed packet!");
                println!(
                    "Payload: {:?}",
                    String::from_utf8_lossy(trusted_packet.payload())
                );
            }
            Ok(None) => println!("Packet was dropped (probably duplicate)"),
            Err(e) => println!("Error processing packet: {}", e),
        }
    }

    // Run maintenance
    network.maintenance();

    Ok(())
}
