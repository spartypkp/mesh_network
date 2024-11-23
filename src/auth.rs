// auth.rs
#![no_std]

use crate::{
    error::{AuthError, PacketError},
    packet::{PublicKey, Signature},
    Error,
};
use core::time::Duration;
use heapless::{FnvIndexMap, Vec as HVec};
use ring::signature::{self, KeyPair, VerificationAlgorithm};

// Constants
const MAX_DELEGATIONS: usize = 8; // Maximum delegations per node
const MAX_CHAIN_LEN: usize = 4; // Maximum length of auth chain

/// Rights that can be delegated to nodes
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rights {
    /// Can this node route packets?
    pub can_route: bool,
    /// Can this node delegate rights?
    pub can_delegate: bool,
    /// Can this node authorize routes?
    pub can_authorize_routes: bool,
    /// When do these rights expire?
    pub expires_at: u64, // Unix timestamp in milliseconds
}

/// A delegation of rights from one node to another
#[derive(Clone, Debug)]
pub struct Delegation {
    /// Public key of delegated node
    pub to: PublicKey,
    /// Rights being granted
    pub rights: Rights,
    /// Signature authorizing delegation
    pub signature: Signature,
}

/// Authorization tree for rights management
#[derive(Debug)]
pub struct AuthTree {
    /// Our node's public key
    pub keypair: PublicKey,
    /// Our current rights
    pub rights: Rights,
    /// Delegations we've granted
    delegations: HVec<Delegation, MAX_DELEGATIONS>,
    /// Time provider for expiry checks
    time_provider: fn() -> u64,
}

impl AuthTree {
    /// Create new authorization tree
    pub fn new(keypair: PublicKey, rights: Rights, time_provider: fn() -> u64) -> Self {
        Self {
            keypair,
            rights,
            delegations: HVec::new(),
            time_provider,
        }
    }

    /// Verify a signature chain
    pub fn verify_chain(
        &self,
        chain: &[Signature],
        required_rights: Rights,
    ) -> Result<bool, Error> {
        // Empty chain is invalid
        if chain.is_empty() {
            return Err(Error::Auth(AuthError::InvalidChain));
        }

        // Get current time
        let now = (self.time_provider)();

        // Start with root rights
        let mut current_rights = self.rights;

        // Verify each signature in chain
        for (i, sig) in chain.iter().enumerate() {
            // Check if rights have expired
            if current_rights.expires_at < now {
                return Err(Error::Auth(AuthError::RightsExpired));
            }

            // Verify signature grants required rights
            if !self.verify_signature(sig, current_rights) {
                return Err(Error::Auth(AuthError::InvalidSignature));
            }

            // Get rights from delegation
            if let Some(delegation) = self.find_delegation(sig) {
                current_rights = delegation.rights;
            } else {
                return Err(Error::Auth(AuthError::InvalidDelegation));
            }
        }

        Ok(self.rights_satisfy(current_rights, required_rights))
    }

    /// Delegate rights to another node
    pub fn delegate_rights(
        &mut self,
        to: PublicKey,
        rights: Rights,
        keypair: &ring::signature::Ed25519KeyPair,
    ) -> Result<Signature, Error> {
        // Get current time
        let now = (self.time_provider)();

        // Verify we have delegation rights
        if !self.rights.can_delegate || self.rights.expires_at < now {
            return Err(Error::Auth(AuthError::InsufficientRights));
        }

        // Verify rights are subset of ours
        if !self.rights_satisfy(self.rights, rights) {
            return Err(Error::Auth(AuthError::InvalidDelegation));
        }

        // Create and sign delegation
        let mut msg = HVec::<u8, 64>::new();
        msg.extend_from_slice(&to)
            .map_err(|_| Error::Packet(PacketError::SizeExceeded))?;
        msg.extend_from_slice(&rights.to_bytes())
            .map_err(|_| Error::Packet(PacketError::SizeExceeded))?;

        let signature = keypair.sign(&msg);

        // Store delegation
        let delegation = Delegation {
            to,
            rights,
            signature: signature
                .as_ref()
                .try_into()
                .map_err(|_| Error::Auth(AuthError::InvalidSignature))?,
        };

        self.delegations
            .push(delegation)
            .map_err(|_| Error::Auth(AuthError::TooManyDelegations))?;

        signature
            .as_ref()
            .try_into()
            .map_err(|_| Error::Auth(AuthError::InvalidSignature))
    }

    /// Verify routing rights
    pub fn verify_routing_rights(&self, chain: &[Signature]) -> Result<bool, Error> {
        let required = Rights {
            can_route: true,
            can_delegate: false,
            can_authorize_routes: false,
            expires_at: (self.time_provider)(),
        };
        self.verify_chain(chain, required)
    }

    pub fn verify_route_auth(&self, chain: &[Signature]) -> Result<bool, Error> {
        let required = Rights {
            can_route: true,
            can_delegate: false,
            can_authorize_routes: true,
            expires_at: (self.time_provider)(),
        };
        self.verify_chain(chain, required)
    }

    // Private helper functions

    fn verify_signature(&self, signature: &Signature, rights: Rights) -> bool {
        // Verify signature grants these rights
        // Implementation depends on signature format
        true // Placeholder
    }

    fn find_delegation(&self, signature: &Signature) -> Option<&Delegation> {
        self.delegations.iter().find(|d| d.signature == *signature)
    }

    fn rights_satisfy(&self, held: Rights, required: Rights) -> bool {
        // Check each right
        ((!required.can_route || held.can_route) &&
         (!required.can_delegate || held.can_delegate) &&
         (!required.can_authorize_routes || held.can_authorize_routes)) &&
        // Check expiry
        held.expires_at >= required.expires_at
    }
}

impl Rights {
    fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        // Pack rights into bytes
        bytes[0] = u8::from(self.can_route);
        bytes[1] = u8::from(self.can_delegate);
        bytes[2] = u8::from(self.can_authorize_routes);
        bytes[8..16].copy_from_slice(&self.expires_at.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_time() -> u64 {
        1000 // Fixed timestamp for testing
    }

    #[test]
    fn test_rights_verification() {
        let keypair = [0u8; 32];
        let rights = Rights {
            can_route: true,
            can_delegate: true,
            can_authorize_routes: true,
            expires_at: 2000,
        };

        let auth_tree = AuthTree::new(keypair, rights, test_time);
        let required = Rights {
            can_route: true,
            can_delegate: false,
            can_authorize_routes: false,
            expires_at: 1500,
        };

        // Test with empty chain (should be error)
        let empty_chain: &[Signature] = &[];
        assert!(matches!(
            auth_tree.verify_routing_rights(empty_chain),
            Err(Error::Auth(AuthError::InvalidChain))
        ));

        // Test with expired rights
        let expired_rights = Rights {
            expires_at: 0,
            ..rights
        };
        let auth_tree = AuthTree::new(keypair, expired_rights, test_time);
        assert!(matches!(
            auth_tree.verify_routing_rights(empty_chain),
            Err(Error::Auth(AuthError::RightsExpired))
        ));
    }
    #[test]
    fn test_expired_rights() {
        let keypair = [0u8; 32];
        let rights = Rights {
            can_route: true,
            can_delegate: true,
            can_authorize_routes: true,
            expires_at: 500, // Expired
        };

        let auth_tree = AuthTree::new(keypair, rights, test_time);

        // Verify expired rights fail
        let chain = []; // Empty chain for simple test
        assert!(matches!(
            auth_tree.verify_routing_rights(&chain),
            Err(Error::Auth(AuthError::RightsExpired))
        ));
    }
}
