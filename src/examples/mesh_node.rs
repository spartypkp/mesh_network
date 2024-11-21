// examples/mesh_node.rs
use mesh_network::{
    crypto::{CryptoConfig, CryptoManager},
    logging::LogConfig,
    mesh::{MeshConfig, MeshNode},
    network::NetworkConfig,
    routing::RouterConfig,
    validation::ValidationConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keypair for our node
    let keypair = CryptoManager::generate_keypair()?;

    // Create configuration
    let config = MeshConfig {
        crypto: CryptoConfig::default(),
        network: NetworkConfig::default(),
        routing: RouterConfig::default(),
        validation: ValidationConfig::default(),
        logging: LogConfig::default(),
    };

    // Create mesh node
    let mut node = MeshNode::new(keypair, config).await?;
    println!("Mesh node initialized with ID: {:?}", node.node_id());

    // Example packet handling (in real usage, this would come from radio)
    let example_packet = vec![/* packet data would go here */];
    match node.handle_packet(&example_packet).await {
        Ok(_) => println!("Packet handled successfully"),
        Err(e) => println!("Error handling packet: {}", e),
    }

    // Periodic maintenance
    node.maintenance();

    Ok(())
}
