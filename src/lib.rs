// lib.rs
#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{mem, slice, time::Duration};
use hashbrown::HashMap;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use zerocopy::{AsBytes, FromBytes};

// Internal modules
pub mod auth;
pub mod error;
pub mod packet;

// Re-exports
pub use auth::{AuthTree, Rights};
pub use error::{AuthError, Error, PacketError, RoutingError, TransmitError};
pub use packet::{Packet, PathVector, PublicKey, Signature, TrustedPacket};

/// Routing update information
type RouteUpdate = (PublicKey, PathVector, Vec<Signature>);

/// Time provider for no_std timestamp handling
#[derive(Clone, Copy)]
pub struct TimeProvider {
    pub get_timestamp: fn() -> u64, // Unix timestamp in milliseconds
}

/// Abstract interface for network transmission
pub trait Transmitter {
    /// Attempt to transmit bytes over the network
    fn transmit(&mut self, bytes: &[u8]) -> Result<(), Error>;

    /// Check if transmission is currently possible
    fn can_transmit(&self) -> bool;
}

/// Internal routing table structure
#[derive(Default)]
struct RouteTable {
    /// Full path vectors (only for routing nodes)
    paths: HashMap<PublicKey, PathVector>,

    /// Next hop for non-routing nodes
    next_hop: Option<PublicKey>,
}

/// Main network implementation
pub struct Network<T: Transmitter> {
    /// Node's keypair for signing
    keypair: Ed25519KeyPair,

    /// Network's public key for validation
    network_key: PublicKey,

    /// Abstract transmitter implementation
    transmitter: T,

    /// Optional routing table (None for non-routing nodes)
    routes: Option<RouteTable>,

    /// Authorization tree for rights management
    auth: AuthTree,

    /// Whether this node is a router
    is_router: bool,

    /// Time provider for timestamp operations
    time_provider: TimeProvider,
}

impl<T: Transmitter> Network<T> {
    /// Create a new network instance
    pub fn new(
        transmitter: T,
        keypair: Ed25519KeyPair,
        network_key: [u8; 32],
        is_router: bool,
        time_provider: TimeProvider,
    ) -> Self {
        let routes = if is_router {
            Some(RouteTable::default())
        } else {
            None
        };

        let rights = Rights {
            can_route: is_router,
            can_delegate: true,
            can_authorize_routes: is_router,
            expires_at: (time_provider.get_timestamp)() + 365 * 24 * 60 * 60 * 1000, // 1 year
        };

        // Get public key before moving keypair
        let public_key = keypair.public_key().as_ref().try_into().unwrap();

        Self {
            auth: AuthTree::new(public_key, rights, time_provider.get_timestamp),
            keypair, // keypair is moved here
            network_key,
            transmitter,
            routes,
            is_router,
            time_provider,
        }
    }

    /// Process incoming network packet
    pub fn accept(&mut self, bytes: &[u8]) -> Option<TrustedPacket> {
        // Parse packet
        let mut packet = Packet::from_bytes(bytes).ok()?;

        // Verify authorization chain
        if self
            .auth
            .verify_chain(
                &packet.auth_chain(),
                Rights {
                    can_route: true,
                    can_delegate: false,
                    can_authorize_routes: false,
                    expires_at: (self.time_provider.get_timestamp)(),
                },
            )
            .ok()?
        {
            return None;
        }

        // Handle based on destination
        if packet.destination() == self.keypair.public_key().as_ref() {
            self.process_local(packet)
        } else {
            // Forward packet
            let _ = self.handle_forward(packet);
            None
        }
    }

    /// Send a message to a destination
    pub fn send(&mut self, destination: PublicKey, content: &[u8]) -> Result<(), Error> {
        // Create packet
        let mut packet = Packet::new(
            self.keypair.public_key().as_ref().to_vec(),
            destination.to_vec(),
            content.to_vec(),
        )?;

        // Add authorization chain
        packet.set_auth_chain(self.auth.create_chain()?);

        // Handle routing
        if self.is_router {
            self.compute_path(&mut packet)?;
        }

        // Transmit packet
        self.transmitter.transmit(&packet.to_bytes()?)
    }

    /// Update routing table with new information
    pub fn update_routes(&mut self, update: RouteUpdate) -> Result<(), Error> {
        let (dest, path, signatures) = update;

        // Verify update authorization
        if !self.auth.verify_route_auth(&signatures).unwrap_or(false) {
            return Err(Error::Auth(AuthError::InvalidSignature));
        }

        // Update routes based on node type
        if self.is_router {
            if let Some(routes) = &mut self.routes {
                routes.paths.insert(dest, path);
            }
        } else {
            if let Some(routes) = &mut self.routes {
                routes.next_hop = path.hops.first().cloned();
            }
        }

        Ok(())
    }

    // Private helper functions

    /// Process locally destined packet
    fn process_local(&self, packet: Packet) -> Option<TrustedPacket> {
        Some(TrustedPacket::new(packet))
    }

    /// Handle packet forwarding
    fn handle_forward(&mut self, mut packet: Packet) -> Result<(), Error> {
        let next_hop = if let Some(routes) = &self.routes {
            if self.is_router {
                packet.path_ref().hops.first().cloned()
            } else {
                routes.next_hop.clone()
            }
        } else {
            return Err(Error::Routing(RoutingError::NoRoute));
        };

        if let Some(hop) = next_hop {
            if self.is_router {
                packet.truncate_path();
            }
            self.transmitter.transmit(&packet.to_bytes()?)
        } else {
            Err(Error::Routing(RoutingError::NoRoute))
        }
    }

    /// Compute path vector for routing nodes
    fn compute_path(&self, packet: &mut Packet) -> Result<(), Error> {
        if let Some(routes) = &self.routes {
            if let Some(path) = routes.paths.get(&packet.destination()) {
                packet.set_path(path.clone());
                Ok(())
            } else {
                Err(Error::Routing(RoutingError::NoRoute))
            }
        } else {
            Err(Error::Routing(RoutingError::NotRouter))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock transmitter for testing
    struct MockTransmitter {
        can_transmit: bool,
    }

    impl Transmitter for MockTransmitter {
        fn transmit(&mut self, _bytes: &[u8]) -> Result<(), Error> {
            if self.can_transmit {
                Ok(())
            } else {
                Err(Error::Transmit(TransmitError::SendFailed))
            }
        }

        fn can_transmit(&self) -> bool {
            self.can_transmit
        }
    }

    fn test_time() -> u64 {
        1000 // Fixed timestamp for testing
    }

    #[test]
    fn test_network_creation() {
        let transmitter = MockTransmitter { can_transmit: true };
        let rng = ring::rand::SystemRandom::new();
        let keypair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(keypair.as_ref()).unwrap();

        let time_provider = TimeProvider {
            get_timestamp: test_time,
        };

        let network = Network::new(transmitter, keypair, [0u8; 32], true, time_provider);

        assert!(network.is_router);
        assert!(network.routes.is_some());
    }
}
