// src/validation.rs
use crate::error::MeshError;
use crate::packet::{PacketHeader, PacketType, TrustedPacket, UntrustedPacket};
use ring::digest::{Context, SHA256};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Validates advanced security rules for packets
#[derive(Debug)]
pub struct ValidationRules {
    /// Recently seen nonces to prevent replay attacks
    recent_nonces: Arc<Mutex<HashSet<[u8; 8]>>>,
    /// Nonce timestamp window
    nonce_window: Duration,
    /// Maximum packet age
    max_packet_age: Duration,
    /// Required packet types per source
    required_types: HashSet<(PacketType, [u8; 32])>,
    /// Packet size limits per type
    size_limits: HashMap<PacketType, usize>,
}

impl ValidationRules {
    pub fn new() -> Self {
        let mut size_limits = HashMap::new();
        size_limits.insert(PacketType::Data, 1024 * 64); // 64KB for data
        size_limits.insert(PacketType::Control, 1024); // 1KB for control
        size_limits.insert(PacketType::Discovery, 512); // 512B for discovery
        size_limits.insert(PacketType::Error, 1024); // 1KB for errors

        Self {
            recent_nonces: Arc::new(Mutex::new(HashSet::new())),
            nonce_window: Duration::from_secs(300), // 5 minutes
            max_packet_age: Duration::from_secs(60), // 1 minute
            required_types: HashSet::new(),
            size_limits,
        }
    }

    /// Validates a packet against all security rules
    pub fn validate_packet(&self, packet: &UntrustedPacket) -> Result<(), MeshError> {
        // Check packet size limits
        self.check_size_limits(packet)?;

        // Validate nonce
        self.validate_nonce(packet.header())?;

        // Check packet age
        self.check_packet_age(packet.header())?;

        // Validate required packet types
        self.validate_packet_type(packet.header())?;

        Ok(())
    }

    /// Checks if packet size is within limits for its type
    fn check_size_limits(&self, packet: &UntrustedPacket) -> Result<(), MeshError> {
        let packet_type = PacketType::try_from(packet.header().packet_type)?;
        let size_limit = self
            .size_limits
            .get(&packet_type)
            .ok_or_else(|| MeshError::ValidationError("Unknown packet type".to_string()))?;

        if packet.payload().len() > *size_limit {
            return Err(MeshError::ValidationError(format!(
                "Packet exceeds size limit for type {:?}",
                packet_type
            )));
        }

        Ok(())
    }

    /// Validates nonce to prevent replay attacks
    fn validate_nonce(&self, header: &PacketHeader) -> Result<(), MeshError> {
        let mut nonces = self
            .recent_nonces
            .lock()
            .map_err(|_| MeshError::InternalError("Failed to lock nonce set".to_string()))?;

        // Check if nonce was recently seen
        if nonces.contains(&header.nonce) {
            return Err(MeshError::ValidationError(
                "Duplicate nonce detected".to_string(),
            ));
        }

        // Add new nonce
        nonces.insert(header.nonce);

        Ok(())
    }

    /// Checks if packet is within acceptable age range
    fn check_packet_age(&self, header: &PacketHeader) -> Result<(), MeshError> {
        let nonce_timestamp =
            SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from_be_bytes(header.nonce));

        let age = SystemTime::now()
            .duration_since(nonce_timestamp)
            .map_err(|_| MeshError::ValidationError("Invalid packet timestamp".to_string()))?;

        if age > self.max_packet_age {
            return Err(MeshError::ValidationError("Packet too old".to_string()));
        }

        Ok(())
    }

    /// Validates required packet types for source
    fn validate_packet_type(&self, header: &PacketHeader) -> Result<(), MeshError> {
        let packet_type = PacketType::try_from(header.packet_type)?;

        // Check if this source requires specific packet types
        let required = (packet_type, header.source_id);
        if self.required_types.contains(&required) {
            return Ok(());
        }

        // If no specific requirements, allow common types
        match packet_type {
            PacketType::Data | PacketType::Discovery => Ok(()),
            _ => Err(MeshError::ValidationError(format!(
                "Unauthorized packet type {:?} from source",
                packet_type
            ))),
        }
    }

    /// Clean up old nonces periodically
    pub fn maintenance(&self) {
        let mut nonces = self.recent_nonces.lock().unwrap();
        nonces.clear(); // In production, we'd be more selective
    }

    /// Add required packet type for a source
    pub fn add_required_type(&mut self, packet_type: PacketType, source: [u8; 32]) {
        self.required_types.insert((packet_type, source));
    }

    /// Get size limit for a packet type
    pub fn get_size_limit(&self, packet_type: &PacketType) -> Option<&usize> {
        self.size_limits.get(packet_type)
    }

    /// Set size limit for a packet type
    pub fn set_size_limit(&mut self, packet_type: PacketType, limit: usize) {
        self.size_limits.insert(packet_type, limit);
    }
}
