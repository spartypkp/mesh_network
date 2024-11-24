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

// Core packet structure
#[derive(Clone, Debug)]
pub struct Packet {
    source: PublicKey,
    destination: PublicKey,
    path: PathVector,
    content: Vec<u8>,
    signatures: Vec<Signature>,
}

#[derive(Clone, Debug, Default)]
pub struct PathVector {
    hops: Vec<PublicKey>,
}
impl PathVector {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();

        // Write number of hops
        bytes.extend_from_slice(&(self.hops.len() as u16).to_le_bytes());

        // Write each hop
        for hop in &self.hops {
            bytes.extend_from_slice(&(hop.len() as u16).to_le_bytes());
            bytes.extend_from_slice(hop);
        }

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0;

        // Read number of hops
        if bytes.len() < 2 {
            return Err(Error::Packet(PacketError::InvalidFormat));
        }
        let hop_count = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;

        let mut hops = Vec::with_capacity(hop_count);

        // Read each hop
        for _ in 0..hop_count {
            if pos + 2 > bytes.len() {
                return Err(Error::Packet(PacketError::InvalidFormat));
            }
            let hop_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;

            if pos + hop_len > bytes.len() {
                return Err(Error::Packet(PacketError::InvalidFormat));
            }
            hops.push(bytes[pos..pos + hop_len].to_vec());
            pos += hop_len;
        }

        Ok(Self { hops })
    }
}

impl Packet {
    pub fn new(source: PublicKey, destination: PublicKey, content: Vec<u8>) -> Result<Self> {
        Ok(Self {
            source,
            destination,
            path: PathVector::default(),
            content,
            signatures: Vec::new(),
        })
    }

    pub fn destination(&self) -> &[u8] {
        &self.destination
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // Serialize packet format:
        // [source_len(2)][source][dest_len(2)][dest][path_len(2)][path][content_len(4)][content][sigs_count(2)][sigs]
        let mut bytes = Vec::new();

        // Add source
        bytes.extend_from_slice(&(self.source.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.source);

        // Add destination
        bytes.extend_from_slice(&(self.destination.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.destination);

        // Add path
        let path_bytes = self.path.to_bytes()?;
        bytes.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&path_bytes);

        // Add content
        bytes.extend_from_slice(&(self.content.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.content);

        // Add signatures
        bytes.extend_from_slice(&(self.signatures.len() as u16).to_le_bytes());
        for sig in &self.signatures {
            bytes.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            bytes.extend_from_slice(sig);
        }

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0;

        // Read source
        let source_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        let source = bytes[pos..pos + source_len].to_vec();
        pos += source_len;

        // Read destination
        let dest_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        let destination = bytes[pos..pos + dest_len].to_vec();
        pos += dest_len;

        // Read path
        let path_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        let path = PathVector::from_bytes(&bytes[pos..pos + path_len])?;
        pos += path_len;

        // Read content
        let content_len =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;
        let content = bytes[pos..pos + content_len].to_vec();
        pos += content_len;

        // Read signatures
        let sig_count = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        let mut signatures = Vec::with_capacity(sig_count);

        for _ in 0..sig_count {
            let sig_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;
            signatures.push(bytes[pos..pos + sig_len].to_vec());
            pos += sig_len;
        }

        Ok(Self {
            source,
            destination,
            path,
            content,
            signatures,
        })
    }
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
