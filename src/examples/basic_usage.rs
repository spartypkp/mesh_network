// examples/basic_usage.rs
use mesh_network::{MeshConfig, MeshNetwork};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create default configuration
    let config = MeshConfig::default();

    // Initialize the mesh network
    let mesh = MeshNetwork::new(config);

    // Example radio packet (just dummy data for now)
    let dummy_packet = vec![
        0x4D, 0x45, 0x53, 0x48, // Magic "MESH"
        0x01, // Version
        0x00, // Packet type
        0x00, 0x0A, // Payload length (10 bytes)
              // ... rest will be implemented later
    ];

    // Try to process the packet
    match mesh.process_packet(&dummy_packet) {
        Ok(Some(trusted_packet)) => {
            println!("Successfully validated packet!");
        }
        Ok(None) => {
            println!("Packet was invalid but no error occurred");
        }
        Err(e) => {
            println!("Error processing packet: {:?}", e);
        }
    }

    Ok(())
}
