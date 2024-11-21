// examples/packet_parsing.rs
use mesh_network::packet::{PacketHeader, UntrustedPacket, PACKET_MAGIC};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Construct raw packet
    packet_data.extend_from_slice(header.as_bytes());
    packet_data.extend_from_slice(b"Hello"); // Payload
    packet_data.extend_from_slice(&[0u8; 64]); // Dummy signature

    // Try to parse it
    match UntrustedPacket::from_bytes(&packet_data) {
        Ok(packet) => {
            println!("Successfully parsed packet!");
            println!("Header: {:?}", packet.header());
            println!("Payload: {:?}", String::from_utf8_lossy(packet.payload()));
        }
        Err(e) => {
            println!("Failed to parse packet: {}", e);
        }
    }

    Ok(())
}
