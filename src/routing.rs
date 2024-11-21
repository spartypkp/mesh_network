// src/routing.rs
use crate::error::MeshError;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

/// Represents a node in the mesh network
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

/// Represents the link quality between nodes
#[derive(Debug, Clone)]
pub struct LinkQuality {
    /// Signal strength (-100 to 0 dBm)
    signal_strength: i32,
    /// Packet loss rate (0.0 to 1.0)
    loss_rate: f32,
    /// Last updated timestamp
    last_updated: SystemTime,
    /// Number of hops to this node
    hop_count: u8,
}
impl LinkQuality {
    /// Debug method to access last_updated timestamp
    pub fn debug_last_updated(&self) -> SystemTime {
        self.last_updated
    }
}

/// Route metrics used for path selection
#[derive(Debug, Clone)]
pub struct RouteMetrics {
    /// Total path quality (higher is better)
    path_quality: f32,
    /// Total hop count
    hop_count: u8,
    /// Timestamp of last update
    last_updated: SystemTime,
}

impl RouteMetrics {
    /// Create new route metrics (available for testing from other crates)
    pub fn new(path_quality: f32, hop_count: u8, last_updated: SystemTime) -> Self {
        Self {
            path_quality,
            hop_count,
            last_updated,
        }
    }

    /// Internal constructor for production use
    pub(crate) fn new_internal(path_quality: f32, hop_count: u8) -> Self {
        Self {
            path_quality,
            hop_count,
            last_updated: SystemTime::now(),
        }
    }
    /// Debug method to access last_updated timestamp
    pub fn debug_last_updated(&self) -> SystemTime {
        self.last_updated
    }
}

/// Routing table entry
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Next hop to reach destination
    next_hop: NodeId,
    /// Route metrics
    metrics: RouteMetrics,
    /// Path to destination
    path: Vec<NodeId>,
}

impl RouteEntry {
    /// Create a new route entry
    pub(crate) fn new(next_hop: NodeId, metrics: RouteMetrics, path: Vec<NodeId>) -> Self {
        Self {
            next_hop,
            metrics,
            path,
        }
    }

    /// Get the next hop for this route
    pub fn next_hop(&self) -> &NodeId {
        &self.next_hop
    }

    /// Get the route metrics
    pub fn metrics(&self) -> &RouteMetrics {
        &self.metrics
    }

    /// Get the complete path
    pub fn path(&self) -> &[NodeId] {
        &self.path
    }

    /// Get the route quality (0.0 to 1.0)
    pub fn quality(&self) -> f32 {
        self.metrics.path_quality
    }

    /// Get number of hops to destination
    pub fn hop_count(&self) -> u8 {
        self.metrics.hop_count
    }
}

/// Implements advanced routing algorithms for the mesh network
#[derive(Debug)]
pub struct Router {
    /// Our node's ID
    local_id: NodeId,
    /// Known link qualities to neighbors
    link_qualities: HashMap<NodeId, LinkQuality>,
    /// Routing table
    routes: HashMap<NodeId, RouteEntry>,
    /// Configuration
    config: RouterConfig,
}

impl Router {
    pub fn new(local_id: NodeId, config: RouterConfig) -> Self {
        Self {
            local_id,
            link_qualities: HashMap::new(),
            routes: HashMap::new(),
            config,
        }
    }

    /// Debug method to access link quality timestamp
    pub fn debug_link_quality(&self, node: &NodeId) -> Option<SystemTime> {
        self.link_qualities
            .get(node)
            .map(|q| q.debug_last_updated())
    }

    /// Debug method to access route metrics timestamp
    pub fn debug_route_metrics(&self, node: &NodeId) -> Option<SystemTime> {
        self.routes
            .get(node)
            .map(|r| r.metrics.debug_last_updated())
    }

    /// Update link quality to a neighbor
    pub fn update_link_quality(
        &mut self,
        neighbor: NodeId,
        signal_strength: i32,
        loss_rate: f32,
    ) -> Result<(), MeshError> {
        if signal_strength > 0 || signal_strength < -100 {
            return Err(MeshError::NetworkError(
                "Invalid signal strength".to_string(),
            ));
        }

        if loss_rate < 0.0 || loss_rate > 1.0 {
            return Err(MeshError::NetworkError("Invalid loss rate".to_string()));
        }

        // Update link quality
        self.link_qualities.insert(
            neighbor.clone(),
            LinkQuality {
                signal_strength,
                loss_rate,
                last_updated: self.config.now(),
                hop_count: 1,
            },
        );

        // Update or remove direct route based on quality
        if signal_strength >= self.config.min_signal_strength
            && loss_rate <= self.config.max_loss_rate
        {
            // Add/update direct route
            let route = RouteEntry::new(
                neighbor.clone(),
                RouteMetrics::new_internal(1.0 - loss_rate, 1),
                vec![self.local_id.clone(), neighbor.clone()],
            );
            self.routes.insert(neighbor.clone(), route);
        } else {
            // Remove direct route if quality is too poor
            self.routes.remove(&neighbor);
        }

        // Recalculate indirect routes
        self.recalculate_routes(Some(&neighbor));

        Ok(())
    }

    /// Find the best route to a destination
    pub fn find_route(&self, destination: &NodeId) -> Option<RouteEntry> {
        // Don't route to self
        if destination == &self.local_id {
            return None;
        }

        // Check direct connection first
        if let Some(quality) = self.link_qualities.get(destination) {
            // Only use direct route if it meets quality thresholds
            if quality.signal_strength >= self.config.min_signal_strength
                && quality.loss_rate <= self.config.max_loss_rate
            {
                return Some(RouteEntry::new(
                    destination.clone(),
                    RouteMetrics::new_internal(1.0 - quality.loss_rate, 1),
                    vec![self.local_id.clone(), destination.clone()],
                ));
            }
        }

        // Fall back to routing table
        self.routes.get(destination).cloned()
    }

    /// Update routing table with information from a neighbor
    pub fn update_routes(&mut self, from: NodeId, routes: Vec<(NodeId, RouteMetrics)>) {
        let neighbor_quality = match self.link_qualities.get(&from) {
            Some(quality) => quality,
            None => return, // We don't have a direct link to this neighbor
        };

        for (destination, metrics) in routes {
            // Don't route to ourselves
            if destination == self.local_id {
                continue;
            }

            // Calculate new metrics through this neighbor
            let new_metrics = RouteMetrics {
                path_quality: metrics.path_quality * (1.0 - neighbor_quality.loss_rate),
                hop_count: metrics.hop_count + 1,
                last_updated: self.config.now(),
            };

            // Check if this is a better route
            let should_update = match self.routes.get(&destination) {
                Some(existing) => self.is_route_better(&new_metrics, &existing.metrics),
                None => true,
            };

            if should_update && new_metrics.hop_count <= self.config.max_hops {
                let mut path = vec![self.local_id.clone(), from.clone()];
                if let Some(existing) = self.routes.get(&destination) {
                    path.extend(existing.path.iter().cloned());
                }

                self.routes.insert(
                    destination,
                    RouteEntry {
                        next_hop: from.clone(),
                        metrics: new_metrics,
                        path,
                    },
                );
            }
        }
    }

    /// Determine if a new route is better than an existing one
    fn is_route_better(&self, new: &RouteMetrics, existing: &RouteMetrics) -> bool {
        // Prefer routes with better path quality
        if (new.path_quality - existing.path_quality).abs() > 0.1 {
            return new.path_quality > existing.path_quality;
        }

        // If quality is similar, prefer shorter routes
        if new.hop_count != existing.hop_count {
            return new.hop_count < existing.hop_count;
        }

        // If all else is equal, prefer newer routes
        new.last_updated > existing.last_updated
    }

    /// Recalculate routes after a topology change
    fn recalculate_routes(&mut self, changed_node: Option<&NodeId>) {
        let mut visited = HashSet::new();
        let mut to_process = vec![self.local_id.clone()];
        visited.insert(self.local_id.clone());

        // First, get all reachable nodes
        while let Some(current) = to_process.pop() {
            let neighbors: Vec<_> = self
                .link_qualities
                .iter()
                .filter(|(_, quality)| {
                    quality.signal_strength >= self.config.min_signal_strength
                        && quality.loss_rate <= self.config.max_loss_rate
                })
                .map(|(id, _)| id.clone())
                .collect();

            for neighbor in neighbors {
                if !visited.contains(&neighbor) {
                    visited.insert(neighbor.clone());
                    to_process.push(neighbor);
                }
            }
        }

        // Remove unreachable routes
        self.routes.retain(|_, route| {
            visited.contains(&route.next_hop) && route.hop_count() <= self.config.max_hops
        });

        // Update metrics for remaining routes if needed
        if let Some(node) = changed_node {
            if let Some(quality) = self.link_qualities.get(node) {
                for route in self.routes.values_mut() {
                    if route.next_hop() == node {
                        route.metrics =
                            RouteMetrics::new_internal(1.0 - quality.loss_rate, route.hop_count());
                    }
                }
            }
        }
    }

    /// Perform periodic maintenance
    pub fn maintenance(&mut self) {
        let now = self.config.now();

        // Remove old link qualities
        self.link_qualities.retain(|_, quality| {
            now.duration_since(quality.last_updated).unwrap_or_default()
                <= self.config.metric_update_interval
        });

        // Remove stale routes
        self.routes.retain(|_, route| {
            now.duration_since(route.metrics.last_updated)
                .unwrap_or_default()
                <= self.config.metric_update_interval
        });

        // Recalculate all routes
        self.recalculate_routes(None);
    }

    /// Get mutable access to router configuration (primarily for testing)
    pub fn config_mut(&mut self) -> &mut RouterConfig {
        &mut self.config
    }
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// How often to update route metrics
    pub metric_update_interval: Duration,
    /// Maximum acceptable hop count
    pub max_hops: u8,
    /// Minimum acceptable signal strength
    pub min_signal_strength: i32,
    /// Maximum acceptable loss rate
    pub max_loss_rate: f32,
    /// Current time (for testing)
    current_time: SystemTime,
}

impl RouterConfig {
    /// Get the current time
    pub fn now(&self) -> SystemTime {
        if cfg!(test) {
            self.current_time
        } else {
            SystemTime::now()
        }
    }

    /// Advance the current time (for testing purposes)
    pub fn advance_time(&mut self, duration: Duration) {
        // Add nanoseconds to ensure precise time advancement
        let current_nanos = self
            .current_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let new_nanos = current_nanos + duration.as_nanos();

        self.current_time = SystemTime::UNIX_EPOCH + Duration::from_nanos(new_nanos as u64);

        println!(
            "Time advanced from {:?} to {:?} (diff: {:?})",
            self.current_time - duration,
            self.current_time,
            duration
        );
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            metric_update_interval: Duration::from_secs(60),
            max_hops: 10,
            min_signal_strength: -85,
            max_loss_rate: 0.3,
            current_time: SystemTime::now(),
        }
    }
}
