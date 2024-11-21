// src/crypto.rs
use crate::error::MeshError;
use crate::packet::UntrustedPacket;
use ring::signature::{self, Ed25519KeyPair, KeyPair, VerificationAlgorithm};
use std::collections::HashMap;
use zerocopy::AsBytes;
pub struct CryptoManager {
    /// Our node's keypair
    local_keypair: Ed25519KeyPair,
    /// Known public keys of trusted peers
    trusted_keys: HashMap<[u8; 32], Vec<u8>>,
}

impl CryptoManager {
    /// Create a new crypto manager
    pub fn new(keypair: Ed25519KeyPair) -> Self {
        Self {
            local_keypair: keypair,
            trusted_keys: HashMap::new(),
        }
    }

    /// Generate a new keypair
    pub fn generate_keypair() -> Result<Ed25519KeyPair, MeshError> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| MeshError::CryptoError("Failed to generate keypair".to_string()))?;

        Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|_| MeshError::CryptoError("Failed to process keypair".to_string()))
    }

    /// Get the local node's ID (public key)
    pub fn node_id(&self) -> [u8; 32] {
        let mut id = [0u8; 32];
        id.copy_from_slice(self.local_keypair.public_key().as_ref());
        id
    }

    /// Get a new instance of the local keypair
    pub fn local_keypair_owned(&self) -> Ed25519KeyPair {
        Self::generate_keypair().expect("Failed to create new keypair")
    }

    /// Keep the existing local_keypair method for other uses
    pub fn local_keypair(&self) -> &Ed25519KeyPair {
        &self.local_keypair
    }

    /// Add a trusted peer
    pub fn add_trusted_peer(&mut self, peer_id: [u8; 32], public_key: Vec<u8>) {
        self.trusted_keys.insert(peer_id, public_key);
    }

    /// Remove a trusted peer
    pub fn remove_trusted_peer(&mut self, peer_id: &[u8; 32]) {
        self.trusted_keys.remove(peer_id);
    }

    /// Sign a message with local keypair
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.local_keypair.sign(message).as_ref().to_vec()
    }

    /// Verify a packet's signature
    pub fn verify_packet(&self, packet: &UntrustedPacket) -> Result<bool, MeshError> {
        let peer_key = match self.trusted_keys.get(&packet.header().source_id) {
            Some(key) => key,
            None => return Ok(false),
        };

        let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, peer_key);

        // Create message to verify (header + payload)
        let mut message = Vec::new();
        message.extend_from_slice(packet.header().as_bytes());
        message.extend_from_slice(packet.payload());

        peer_public_key
            .verify(&message, packet.signature())
            .map(|_| true)
            .map_err(|_| MeshError::CryptoError("Signature verification failed".to_string()))
    }

    /// Check if a peer is trusted
    pub fn is_trusted_peer(&self, peer_id: &[u8; 32]) -> bool {
        self.trusted_keys.contains_key(peer_id)
    }
}

/// Configuration for cryptographic operations
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Custom parameters if needed
    pub custom_params: Option<HashMap<String, String>>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            custom_params: None,
        }
    }
}
