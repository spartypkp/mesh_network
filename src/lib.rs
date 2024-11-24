#![no_std]
extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{mem, slice};
use hashbrown::HashMap;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use zerocopy::{AsBytes, FromBytes};

// Type definitions
pub type PublicKey = Vec<u8>;
pub type Signature = Vec<u8>;
pub type Result<T> = core::result::Result<T, Error>;

// Error handling
#[derive(Debug)]
pub enum Error {
    Packet(PacketError),
    Auth(AuthError),
    Routing(RoutingError),
    Transmit(TransmitError),
}

#[derive(Debug)]
pub enum PacketError {
    InvalidFormat,
    InvalidSignature,
}

#[derive(Debug)]
pub enum AuthError {
    InvalidRights,
    ExpiredTTL,
}

#[derive(Debug)]
pub enum RoutingError {
    NoRoute,
    NotRouter,
}

#[derive(Debug)]
pub enum TransmitError {
    BufferFull,
    DeviceError,
}

pub const MAX_PACKET_SIZE: usize = 1024; // Or whatever size limit you need

// Core packet structure
#[derive(Clone, Debug, FromBytes, ToBytes)]
pub struct Packet<'a, const S: usize> {
    destination: PublicKey,
    content: PacketBody<'a, S>,
    sig: Signature, // packet source is the public key of the signature
}

#[derive(Clone, Debug, Copy, FromBytes, ToBytes)]
pub enum PacketBody<'a, const S: usize> {
    Forward(&'a Packet<'a, S>), // Sending next node this packet to forward. Route already determined by sender (me)
    Content(&'a Vec<u8>),       // Here's some data yo
    Routable(&'a Packet<'a, S>), // Here's some packet, I don't know where to send it, fucking deal with it.
}
// Claude's fix:
#[derive(AsBytes, FromBytes)]
#[repr(C)]
pub struct SignedContent {
    destination_len: u32,
    content_len: u32,
}
// Evan's implementation:
// impl<'a, const S: usize> Packet<'a, S> {
//     pub fn new<K: KeyPair>(
//         source: K,
//         destination: PublicKey,
//         content: &'a Vec<u8>,
//     ) -> Result<Self> {
//
//         let sig = source.sign(content.as_bytes()); // FIXME: security hole (sign dest too)
//         Ok(Self {
//             destination,
//             content: PacketBody::Content(content),
//             sig,
//         })
//     }
// }

impl<'a, const S: usize> Packet<'a, S> {
    pub fn new(
        source: &Ed25519KeyPair,
        destination: PublicKey,
        content: &'a Vec<u8>,
    ) -> Result<Self> {
        // Create the signed content header
        let header = SignedContent {
            destination_len: destination.len() as u32,
            content_len: content.len() as u32,
        };

        // Calculate total buffer size and create buffer
        let total_size = mem::size_of::<SignedContent>() + destination.len() + content.len();
        let mut signing_buffer = Vec::with_capacity(total_size);

        // Build the buffer in a structured way
        signing_buffer.extend_from_slice(header.as_bytes());
        signing_buffer.extend_from_slice(&destination);
        signing_buffer.extend_from_slice(content);

        let sig = source.sign(&signing_buffer).as_ref().to_vec();

        Ok(Self {
            destination,
            content: PacketBody::Content(content),
            sig,
        })
    }

    pub fn destination(&self) -> &[u8] {
        &self.destination
    }
    // Implementing a serialization format for the Packet structure
    // Convert
}

// Authorization structure
#[derive(Clone, Debug)]
pub struct Rights {
    can_route: bool,
    can_manage: bool,
    ttl: u64,
}

#[derive(Default)]
pub struct AuthTree {
    rights: HashMap<PublicKey, Rights>,
}

impl AuthTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant_rights(&mut self, to: PublicKey, rights: Rights) {
        self.rights.insert(to, rights);
    }

    pub fn verify_rights(&self, key: &PublicKey, required: &Rights) -> Result<()> {
        match self.rights.get(key) {
            Some(rights)
                if rights.ttl > 0
                    && rights.can_route >= required.can_route
                    && rights.can_manage >= required.can_manage =>
            {
                Ok(())
            }
            _ => Err(Error::Auth(AuthError::InvalidRights)),
        }
    }
}

// Transmitter trait
pub trait Transmitter {
    fn transmit(&mut self, bytes: &[u8]) -> Result<()>;
    fn can_transmit(&self) -> bool;
}

// Route table
#[derive(Default)]
struct RouteTable {
    paths: HashMap<PublicKey, PathVector>,
    next_hop: Option<PublicKey>,
}

// Main network structure
pub struct Network<T: Transmitter> {
    transmitter: T,
    keypair: Ed25519KeyPair,
    network_key: PublicKey,
    routes: Option<RouteTable>,
    auth_tree: AuthTree,
    is_router: bool,
}

// Trusted packet wrapper
pub struct TrustedPacket(Packet);

impl TrustedPacket {
    pub fn new(packet: Packet) -> Self {
        Self(packet)
    }

    pub fn content(&self) -> &[u8] {
        &self.0.content
    }
}

impl<T: Transmitter> Network<T> {
    pub fn new(
        transmitter: T,
        keypair: Ed25519KeyPair,
        network_key: PublicKey,
        is_router: bool,
    ) -> Self {
        let routes = if is_router {
            Some(RouteTable::default())
        } else {
            None
        };

        Self {
            transmitter,
            keypair,
            network_key,
            routes,
            auth_tree: AuthTree::new(),
            is_router,
        }
    }

    pub fn accept(&mut self, bytes: &[u8]) -> Option<TrustedPacket> {
        let packet = Packet::from_bytes(bytes).ok()?;

        // Verify destination
        if packet.destination() == self.keypair.public_key().as_ref() {
            // Verify signatures using auth tree
            for sig in &packet.signatures {
                // In real implementation, verify signature chain here
                // For now, we just accept all signatures
            }
            Some(TrustedPacket::new(packet))
        } else if self.is_router {
            // Forward packet if we're a router
            let _ = self.forward_packet(&packet);
            None
        } else {
            None
        }
    }

    pub fn send(&mut self, dest: PublicKey, content: &[u8]) -> Result<()> {
        let mut packet = Packet::new(
            self.keypair.public_key().as_ref().to_vec(),
            dest,
            content.to_vec(),
        )?;

        // If router, compute path
        if self.is_router {
            self.compute_path(&mut packet)?;
        }

        // Sign packet
        let signature = self.keypair.sign(content);
        packet.signatures.push(signature.as_ref().to_vec());

        // Transmit
        self.transmitter.transmit(&packet.to_bytes()?)
    }

    fn forward_packet(&mut self, packet: &Packet) -> Result<()> {
        // Get next hop from route table
        let next_hop = self
            .routes
            .as_ref()
            .and_then(|routes| routes.next_hop.clone())
            .ok_or(Error::Routing(RoutingError::NoRoute))?;

        // Create forwarded packet with truncated path
        let mut forwarded = packet.clone();
        if !forwarded.path.hops.is_empty() {
            forwarded.path.hops.remove(0);
        }

        self.transmitter.transmit(&forwarded.to_bytes()?)
    }

    fn compute_path(&self, packet: &mut Packet) -> Result<()> {
        if let Some(routes) = &self.routes {
            if let Some(path) = routes.paths.get(&packet.destination) {
                packet.path = path.clone();
                Ok(())
            } else {
                Err(Error::Routing(RoutingError::NoRoute))
            }
        } else {
            Err(Error::Routing(RoutingError::NotRouter))
        }
    }
}
