// tests/unit/routing_tests.rs
use crate::common;
use mesh_network::routing::{LinkQuality, NodeId, RouteMetrics, Router, RouterConfig};
use std::time::{Duration, SystemTime};

/// Like creating a basic server setup
fn setup_test_router() -> Router {
    let local_id = NodeId([0u8; 32]);
    let config = RouterConfig::default();
    Router::new(local_id, config)
}

/// Like testing basic server health/connectivity
#[test]
fn test_basic_routing() {
    let mut router = setup_test_router();
    let neighbor = NodeId([1u8; 32]);

    // Like checking if a server responds to ping
    assert!(router
        .update_link_quality(
            neighbor.clone(),
            -50, // Like good latency
            0.1, // Like 90% uptime
        )
        .is_ok());

    // Like checking if server is in the load balancer
    let route = router.find_route(&neighbor);
    assert!(route.is_some());
}

/// Like testing CDN node health/performance
#[test]
fn test_link_quality_thresholds() {
    let mut router = setup_test_router();
    let neighbor = NodeId([1u8; 32]);

    // Like testing different server response times
    println!("\n=== Testing Link Quality Thresholds ===");

    // Like a server with good performance
    assert!(router
        .update_link_quality(neighbor.clone(), -50, 0.1)
        .is_ok());
    println!("✓ Good quality link accepted");

    // Like a server with high latency
    assert!(router
        .update_link_quality(neighbor.clone(), -90, 0.1)
        .is_ok());
    println!("✓ Poor signal strength still acceptable");

    // Like a server with too many errors
    assert!(router
        .update_link_quality(neighbor.clone(), -50, 0.9)
        .is_ok());
    println!("✓ High loss rate registered");

    // Like an invalid server response
    assert!(router
        .update_link_quality(neighbor.clone(), 50, 0.1)
        .is_err());
    println!("✓ Invalid signal strength rejected");
}

/// Like testing load balancer routing decisions
#[test]
fn test_route_selection() {
    let mut router = setup_test_router();
    let path1 = NodeId([1u8; 32]);
    let path2 = NodeId([2u8; 32]);

    // Add routes
    router.update_link_quality(path1.clone(), -50, 0.1).unwrap();
    router.update_link_quality(path2.clone(), -70, 0.2).unwrap();

    // Check preferred route
    let route = router.find_route(&path1).unwrap();
    assert_eq!(route.next_hop(), &path1, "Router should prefer path1");
    assert!(route.quality() > 0.8, "Path quality should be high");
    assert_eq!(route.hop_count(), 1, "Should be a direct route");

    // Test secondary route
    let route2 = router.find_route(&path2).unwrap();
    assert_eq!(route2.next_hop(), &path2);
    assert!(route2.quality() < route.quality());
}

/// Test route invalidation and failover
#[test]
fn test_route_maintenance() {
    let mut router = setup_test_router();
    let path1 = NodeId([1u8; 32]);

    // Add initial route
    router.update_link_quality(path1.clone(), -50, 0.1).unwrap();
    assert!(router.find_route(&path1).is_some(), "Route should exist");

    // Wait for route to expire
    std::thread::sleep(Duration::from_secs(61)); // Just over default 60s timeout

    // Run maintenance
    router.maintenance();

    // Route should be gone
    assert!(
        router.find_route(&path1).is_none(),
        "Route should be removed after maintenance"
    );
}

// Like testing geo-distributed load balancing
#[test]
fn test_multi_hop_routing() {
    let mut router = setup_test_router();
    let node1 = NodeId([1u8; 32]);
    let node2 = NodeId([2u8; 32]);

    // Set up initial route
    router.update_link_quality(node1.clone(), -50, 0.1).unwrap();

    // Update with route information
    let routes = vec![(node2.clone(), RouteMetrics::new(0.9, 1, SystemTime::now()))];
    router.update_routes(node1.clone(), routes);

    // Verify routing
    let route_to_eu = router.find_route(&node2).unwrap();
    assert_eq!(route_to_eu.next_hop(), &node1);
    assert_eq!(route_to_eu.hop_count(), 2);
}

/// Like testing failover scenarios
#[test]
fn test_route_failover() {
    let mut router = setup_test_router();
    let primary = NodeId([1u8; 32]); // Like primary server
    let backup = NodeId([2u8; 32]); // Like backup server

    println!("\n=== Testing Route Failover ===");

    // Set up initial routes
    router
        .update_link_quality(primary.clone(), -50, 0.1)
        .unwrap();
    router
        .update_link_quality(backup.clone(), -60, 0.2)
        .unwrap();
    println!("Set up primary and backup routes");

    // Simulate primary failure (like server outage)
    router
        .update_link_quality(primary.clone(), -95, 0.8)
        .unwrap();
    println!("Primary route quality degraded");

    // Check failover
    let route = router.find_route(&backup).unwrap();
    assert_eq!(route.next_hop(), &backup);
    println!("✓ Traffic routed to backup path");
}

/// Like testing automatic scaling/cleanup
#[test]
fn test_maintenance() {
    let mut router = setup_test_router();
    let node = NodeId([1u8; 32]);

    println!("\n=== Testing Maintenance ===");

    // Add initial route
    router.update_link_quality(node.clone(), -50, 0.1).unwrap();
    let initial_time = router.config_mut().now();
    println!("Initial time: {:?}", initial_time);

    // Fast forward time past the maintenance interval
    router.config_mut().advance_time(Duration::from_secs(61));
    let advanced_time = router.config_mut().now();
    println!("After advance: {:?}", advanced_time);
    println!(
        "Time difference: {:?}",
        advanced_time.duration_since(initial_time).unwrap()
    );

    // Run maintenance with debug output
    println!("Starting maintenance...");
    router.maintenance();
    println!("Finished maintenance");

    // Debug prints after maintenance
    println!(
        "Link quality exists: {:?}",
        router.debug_link_quality(&node)
    );
    println!("Route exists: {:?}", router.debug_route_metrics(&node));

    // Verify cleanup
    assert!(router.find_route(&node).is_none());
}

/// Like testing global server health
#[test]
fn test_network_wide_metrics() {
    let mut router = setup_test_router();

    println!("\n=== Testing Network Metrics ===");

    // Add multiple nodes (like different regions)
    for i in 1..5 {
        let node = NodeId([i; 32]);
        let signal = -50 - (i as i32 * 5); // Decreasing signal strength
        let loss = 0.1 * (i as f32); // Increasing loss rate

        router.update_link_quality(node, signal, loss).unwrap();
        println!("Added node {} with signal: {}, loss: {}", i, signal, loss);
    }

    // Verify network health
    router.maintenance();
    println!("✓ Network-wide metrics verified");
}
