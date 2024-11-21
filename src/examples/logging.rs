// examples/logging.rs
use mesh_network::logging::{LogConfig, LogLevel, Logger};
use serde_json::json;
use tokio;

#[tokio::main]
async fn main() {
    // Create logger
    let config = LogConfig {
        min_level: LogLevel::Debug,
        buffer_size: 100,
        include_metadata: true,
    };

    let (logger, receiver) = Logger::new(config).await;

    // Spawn log processor
    tokio::spawn(receiver.run());

    // Example usage
    logger.info("Network", "Starting mesh network...").await;

    logger
        .log(
            LogLevel::Info,
            "Packet",
            "Received new packet",
            Some(json!({
                "source": "node1",
                "size": 1024,
                "type": "data"
            })),
        )
        .await
        .unwrap();

    logger.warning("Security", "Rate limit approaching").await;

    logger
        .error("Validation", "Invalid signature detected")
        .await;

    // Give time for logs to process
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
}
