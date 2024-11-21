// src/state.rs
use crate::{
    error::MeshError,
    packet::{TrustedPacket, UntrustedPacket},
};
use ring::signature::{self, KeyPair, VerificationAlgorithm};

#[derive(Debug)]
pub enum ValidationState {
    New,
    HeaderVerified,
    SignatureVerified,
    Complete(TrustedPacket),
    Invalid(MeshError),
}

impl ValidationState {
    /// Start validation of a new packet
    pub fn validate_packet(packet: UntrustedPacket, trusted_key: &[u8]) -> Self {
        // Start validation pipeline
        let state = Self::New;
        state.step(packet, trusted_key)
    }

    /// Advance the validation state machine
    pub fn step(self, packet: UntrustedPacket, trusted_key: &[u8]) -> Self {
        match self {
            ValidationState::New => {
                // First validate the header
                match packet.header().validate() {
                    Ok(()) => ValidationState::HeaderVerified.step(packet, trusted_key),
                    Err(e) => ValidationState::Invalid(e),
                }
            }
            ValidationState::HeaderVerified => {
                // Verify the signature
                match Self::verify_signature(&packet, trusted_key) {
                    Ok(()) => ValidationState::SignatureVerified.step(packet, trusted_key),
                    Err(e) => ValidationState::Invalid(e),
                }
            }
            ValidationState::SignatureVerified => {
                // All validation passed, create trusted packet
                ValidationState::Complete(TrustedPacket::from_untrusted(packet))
            }
            ValidationState::Complete(_) | ValidationState::Invalid(_) => self,
        }
    }

    /// Verify the cryptographic signature on a packet
    fn verify_signature(packet: &UntrustedPacket, public_key: &[u8]) -> Result<(), MeshError> {
        // Create verification key from public key
        let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);

        // Create message to verify (header + payload)
        let mut message = Vec::new();
        message.extend_from_slice(packet.header().as_ref());
        message.extend_from_slice(packet.payload());

        // Verify signature
        peer_public_key
            .verify(&message, packet.signature())
            .map_err(|_| MeshError::CryptoError("Invalid signature".to_string()))
    }
}
