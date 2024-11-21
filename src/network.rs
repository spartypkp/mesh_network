// src/network.rs
use crate::error::MeshError;
use crate::packet::{PacketType, TrustedPacket, UntrustedPacket};
use ring::signature::{self, Ed25519KeyPair, KeyPair}; // Updated import
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use zerocopy::AsBytes;

/// Represents a peer in the mesh network
#[derive(Debug, Clone)]
pub struct Peer {
    /// Public key of the peer
    public_key: Vec<u8>,
    /// Last seen timestamp
    last_seen: SystemTime,
    /// Number of packets received from this peer
    packets_received: u64,
    /// Number of packets forwarded to this peer
    packets_forwarded: u64,
}

impl Peer {
    pub fn new(public_key: Vec<u8>) -> Self {
        Self {
            public_key,
            last_seen: SystemTime::now(),
            packets_received: 0,
            packets_forwarded: 0,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now();
    }

    pub fn increment_received(&mut self) {
        self.packets_received += 1;
        self.update_last_seen();
    }

    pub fn increment_forwarded(&mut self) {
        self.packets_forwarded += 1;
    }
}

/// Configuration for the network manager
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Maximum number of peers allowed
    pub max_peers: usize,
    /// Time after which a peer is considered inactive
    pub peer_timeout: Duration,
    /// Maximum number of hops for packet forwarding
    pub max_hops: u8,
    /// Rate limit for packets per second per peer
    pub rate_limit: u32,
}

/// Represents a forwarding decision for a packet
#[derive(Debug, PartialEq)]
pub enum ForwardingDecision {
    /// Process the packet locally
    Process,
    /// Forward the packet to specified peers
    Forward(Vec<[u8; 32]>),
    /// Both process and forward
    ProcessAndForward(Vec<[u8; 32]>),
    /// Drop the packet
    Drop,
}

/// Metadata about packet forwarding
#[derive(Debug, Clone, Copy)]
pub struct ForwardingMetadata {
    /// Number of hops this packet has taken
    pub hop_count: u8,
    /// Time-to-live for this packet
    pub ttl: u8,
    /// Priority of the packet (0-255)
    pub priority: u8,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_peers: 100,
            peer_timeout: Duration::from_secs(300), // 5 minutes
            max_hops: 5,
            rate_limit: 100, // packets per second
        }
    }
}

/// Manages the mesh network's peer connections and packet forwarding
#[derive(Debug)]
pub struct NetworkManager {
    /// Our node's keypair
    local_keypair: Ed25519KeyPair,
    /// Configuration
    config: NetworkConfig,
    /// Known peers indexed by their ID
    peers: HashMap<[u8; 32], Peer>,
    /// Recently seen packet IDs to prevent loops
    seen_packets: HashSet<[u8; 32]>,
    /// Packet counters for rate limiting
    rate_limits: HashMap<[u8; 32], Vec<SystemTime>>,
}

impl NetworkManager {
    pub fn new(local_keypair: Ed25519KeyPair, config: NetworkConfig) -> Self {
        Self {
            local_keypair,
            config,
            peers: HashMap::new(),
            seen_packets: HashSet::new(),
            rate_limits: HashMap::new(),
        }
    }

    /// Add a new peer to the network
    pub fn add_peer(&mut self, public_key: &[u8]) -> Result<(), MeshError> {
        if self.peers.len() >= self.config.max_peers {
            return Err(MeshError::NetworkError(
                "Maximum peer limit reached".to_string(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(public_key);

        self.peers.insert(key_array, Peer::new(public_key.to_vec()));

        Ok(())
    }

    /// Remove a peer from the network
    pub fn remove_peer(&mut self, public_key: &[u8]) {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(public_key);
        self.peers.remove(&key_array);
        self.rate_limits.remove(&key_array);
    }

    /// Check if a peer is trusted
    pub fn is_trusted_peer(&self, public_key: &[u8]) -> bool {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(public_key);
        self.peers.contains_key(&key_array)
    }

    /// Handle an incoming packet
    pub fn handle_packet(
        &mut self,
        packet: UntrustedPacket,
    ) -> Result<Option<TrustedPacket>, MeshError> {
        // Check if we've seen this packet before
        let packet_id = self.calculate_packet_id(&packet);
        if self.seen_packets.contains(&packet_id) {
            return Ok(None);
        }

        // Check rate limits - just use ? operator directly since it now returns Result<(), MeshError>
        self.check_rate_limit(packet.header().source_id)?;

        // Validate the packet
        let trusted_packet = self.validate_packet(packet)?;

        // Update peer statistics
        if let Some(peer) = self.peers.get_mut(&trusted_packet.header().source_id) {
            peer.increment_received();
        }

        // Add to seen packets
        self.seen_packets.insert(packet_id);

        Ok(Some(trusted_packet))
    }

    /// Calculate a unique ID for a packet to detect duplicates
    fn calculate_packet_id(&self, packet: &UntrustedPacket) -> [u8; 32] {
        use ring::digest::{Context, SHA256};

        let mut context = Context::new(&SHA256);
        context.update(packet.header().as_bytes());
        context.update(packet.payload());

        let digest = context.finish();
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.as_ref());
        id
    }

    /// Check if a peer has exceeded their rate limit
    fn check_rate_limit(&mut self, peer_id: [u8; 32]) -> Result<(), MeshError> {
        let now = SystemTime::now();
        let window_start = now - Duration::from_secs(1);

        // Debug print the peer_id we're checking
        println!("Checking rate limit for peer: {:?}", peer_id);

        // Get or create the peer's packet timestamps
        let timestamps = self.rate_limits.entry(peer_id).or_default();
        println!("Before retention - timestamps count: {}", timestamps.len());

        // Remove old timestamps
        timestamps.retain(|&timestamp| timestamp >= window_start);
        println!("After retention - timestamps count: {}", timestamps.len());

        // Check if we're within the rate limit
        if timestamps.len() >= self.config.rate_limit as usize {
            println!(
                "Rate limit exceeded! Current count: {}, Limit: {}",
                timestamps.len(),
                self.config.rate_limit
            );
            return Err(MeshError::NetworkError("Rate limit exceeded".to_string()));
        }

        // Add new timestamp
        timestamps.push(now);
        println!("Added new timestamp. New count: {}", timestamps.len());

        // Print all timestamps for debugging
        for (i, ts) in timestamps.iter().enumerate() {
            println!(
                "Timestamp {}: {:?} seconds ago",
                i,
                now.duration_since(*ts).unwrap_or_default().as_secs_f32()
            );
        }

        // Debug print all rate limits
        println!("All rate limits:");
        for (id, times) in &self.rate_limits {
            println!("Peer {:?}: {} timestamps", id, times.len());
        }

        Ok(())
    }

    /// Validate an incoming packet
    fn validate_packet(&self, packet: UntrustedPacket) -> Result<TrustedPacket, MeshError> {
        use crate::state::ValidationState;

        let source_id = packet.header().source_id;

        // Debug print to see what we're comparing
        println!("Source ID from packet: {:?}", source_id);
        for (key, _) in &self.peers {
            println!("Stored peer key: {:?}", key);
        }

        // Get the peer's public key
        if !self.is_trusted_peer(&source_id) {
            return Err(MeshError::NetworkError("Untrusted peer".to_string()));
        }

        // Start validation
        let validation_result = ValidationState::validate_packet(packet, &source_id);
        match validation_result {
            ValidationState::Complete(trusted_packet) => Ok(trusted_packet),
            ValidationState::Invalid(e) => Err(e),
            _ => Err(MeshError::ValidationError(
                "Incomplete validation".to_string(),
            )),
        }
    }

    /// Handle packet forwarding
    pub fn forward_packet(
        &mut self,
        packet: &TrustedPacket,
        metadata: ForwardingMetadata,
    ) -> Result<(), MeshError> {
        // Check if we've exceeded max hops
        if metadata.hop_count >= self.config.max_hops {
            return Err(MeshError::NetworkError(
                "Max hop count exceeded".to_string(),
            ));
        }

        // Check TTL
        if metadata.ttl == 0 {
            return Err(MeshError::NetworkError("TTL expired".to_string()));
        }

        // Get forwarding decision
        let decision = self.get_forwarding_decision(packet, metadata)?;

        match decision {
            ForwardingDecision::Forward(peers) | ForwardingDecision::ProcessAndForward(peers) => {
                for peer_id in peers {
                    // First, prepare the send by getting all needed data
                    let send_result = if let Some(peer) = self.peers.get(&peer_id) {
                        self.send_to_peer(&peer, packet, metadata)
                    } else {
                        continue;
                    };

                    // Then handle the counter increment if send was successful
                    if send_result.is_ok() {
                        if let Some(peer_mut) = self.peers.get_mut(&peer_id) {
                            peer_mut.increment_forwarded();
                        }
                    }
                }
            }
            ForwardingDecision::Process => {
                // Process locally - we'll implement this later
            }
            ForwardingDecision::Drop => {
                // Intentionally drop the packet
                return Ok(());
            }
        }

        Ok(())
    }

    /// Determine how to handle a packet
    fn get_forwarding_decision(
        &self,
        packet: &TrustedPacket,
        metadata: ForwardingMetadata,
    ) -> Result<ForwardingDecision, MeshError> {
        // Don't forward if we're the destination
        if packet.header().destination_id == self.get_local_id() {
            return Ok(ForwardingDecision::Process);
        }

        // Get candidate peers for forwarding
        let mut forward_peers = Vec::new();

        for (peer_id, peer) in &self.peers {
            // Don't forward back to source
            if peer_id == &packet.header().source_id {
                continue;
            }

            // Basic routing logic - forward to all peers except source
            // In a real implementation, this would use more sophisticated routing
            forward_peers.push(*peer_id);
        }

        if forward_peers.is_empty() {
            return Ok(ForwardingDecision::Drop);
        }

        // If we're not the destination but should process (e.g., for monitoring)
        if self.should_process_packet(packet) {
            Ok(ForwardingDecision::ProcessAndForward(forward_peers))
        } else {
            Ok(ForwardingDecision::Forward(forward_peers))
        }
    }

    /// Send a packet to a specific peer
    fn send_to_peer(
        &self,
        peer: &Peer,
        packet: &TrustedPacket,
        mut metadata: ForwardingMetadata,
    ) -> Result<(), MeshError> {
        // Update metadata for forwarding
        metadata.hop_count += 1;
        metadata.ttl -= 1;

        // In a real implementation, this would handle the actual network send
        // For now, we'll just simulate it
        println!(
            "Forwarding packet to peer: {:?}, hops: {}, ttl: {}",
            peer.public_key, metadata.hop_count, metadata.ttl
        );

        Ok(())
    }

    /// Get our local node ID
    fn get_local_id(&self) -> [u8; 32] {
        let mut id = [0u8; 32];
        id.copy_from_slice(self.local_keypair.public_key().as_ref());
        id
    }

    /// Determine if we should process a packet locally
    fn should_process_packet(&self, packet: &TrustedPacket) -> bool {
        // Process if we're the destination
        if packet.header().destination_id == self.get_local_id() {
            return true;
        }

        // Process broadcast packets
        if packet.header().destination_id == [0xff; 32] {
            return true;
        }

        // Process certain packet types regardless of destination
        match packet.header().packet_type.try_into().unwrap() {
            PacketType::Discovery => true,
            PacketType::Control => true,
            _ => false,
        }
    }

    /// Clean up old data periodically
    pub fn maintenance(&mut self) {
        let now = SystemTime::now();

        // Remove old peers
        self.peers
            .retain(|_, peer| peer.last_seen + self.config.peer_timeout > now);

        // Clean up rate limit data for removed peers
        self.rate_limits
            .retain(|peer_id, _| self.peers.contains_key(peer_id));

        // Clean up old seen packets (keep last 1000)
        if self.seen_packets.len() > 1000 {
            self.seen_packets.clear();
        }
    }

    /// Get list of peer IDs
    pub fn get_peers(&self) -> Vec<[u8; 32]> {
        self.peers.keys().cloned().collect()
    }
}
