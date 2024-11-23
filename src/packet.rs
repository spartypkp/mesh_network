// packet.rs
#![no_std]

use heapless::{FnvIndexMap, Vec as HVec};
use zerocopy::{AsBytes, FromBytes, Unaligned};

// Type aliases
pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];

// Constants
const MAX_HOPS: usize = 8; // Maximum hops in path vector
const MAX_AUTH_SIGS: usize = 4; // Maximum signatures in auth chain
const MAX_CONTENT: usize = 1024; // Maximum content size

/// Path vector for routing
#[derive(Clone, Debug)]
pub struct PathVector {
    /// Sequence of hops to destination
    hops: HVec<PublicKey, MAX_HOPS>,
    /// Signatures validating the path
    signatures: HVec<Signature, MAX_HOPS>,
}

impl PathVector {
    /// Create new empty path vector
    pub fn new() -> Self {
        Self {
            hops: HVec::new(),
            signatures: HVec::new(),
        }
    }

    /// Truncate path by removing first hop
    pub fn truncate(&mut self) {
        if !self.hops.is_empty() {
            self.hops.remove(0);
            self.signatures.remove(0);
        }
    }

    /// Get next hop in path
    pub fn next_hop(&self) -> Option<PublicKey> {
        self.hops.first().copied()
    }
}

/// Raw packet structure for zero-copy parsing
#[derive(FromBytes, AsBytes, Debug, Unaligned)]
#[repr(C, packed)]
pub struct PacketHeader {
    /// Magic bytes for validation
    pub magic: [u8; 4],
    /// Protocol version
    pub version: u8,
    /// Content length
    pub content_length: u16,
    /// Number of hops in path
    pub hop_count: u8,
    /// Number of signatures in auth chain
    pub sig_count: u8,
    /// Source node
    pub source: PublicKey,
    /// Destination node
    pub destination: PublicKey,
}

/// Untrusted packet before validation
#[derive(Debug)]
pub struct Packet {
    /// Packet header
    header: PacketHeader,
    /// Routing path
    path: PathVector,
    /// Packet content
    content: HVec<u8, MAX_CONTENT>,
    /// Authorization chain
    auth_chain: HVec<Signature, MAX_AUTH_SIGS>,
}

impl Packet {
    /// Create new packet
    pub fn new(source: PublicKey, destination: PublicKey, content: &[u8]) -> Result<Self, Error> {
        let mut packet_content = HVec::new();
        packet_content
            .extend_from_slice(content)
            .map_err(|_| Error::PacketTooLarge)?;

        Ok(Self {
            header: PacketHeader {
                magic: *b"MESH",
                version: 1,
                content_length: content.len() as u16,
                hop_count: 0,
                sig_count: 0,
                source,
                destination,
            },
            path: PathVector::new(),
            content: packet_content,
            auth_chain: HVec::new(),
        })
    }

    /// Parse packet from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Parse header using zerocopy
        let (header, rest) =
            zerocopy::LayoutVerified::<_, PacketHeader>::new_unaligned_from_prefix(bytes)
                .ok_or(Error::InvalidFormat)?;

        let header = header.read();

        // Validate magic bytes
        if header.magic != *b"MESH" {
            return Err(Error::InvalidMagic);
        }

        // Parse path vector
        let mut path = PathVector::new();
        let mut offset = 0;

        for _ in 0..header.hop_count {
            let hop = PublicKey::try_from(&rest[offset..offset + 32])
                .map_err(|_| Error::InvalidFormat)?;
            path.hops.push(hop).map_err(|_| Error::TooManyHops)?;
            offset += 32;
        }

        for _ in 0..header.hop_count {
            let sig = Signature::try_from(&rest[offset..offset + 64])
                .map_err(|_| Error::InvalidFormat)?;
            path.signatures.push(sig).map_err(|_| Error::TooManyHops)?;
            offset += 64;
        }

        // Parse content
        let content_start = offset;
        let content_end = content_start + header.content_length as usize;
        let mut content = HVec::new();
        content
            .extend_from_slice(&rest[content_start..content_end])
            .map_err(|_| Error::PacketTooLarge)?;

        // Parse auth chain
        let mut auth_chain = HVec::new();
        offset = content_end;

        for _ in 0..header.sig_count {
            let sig = Signature::try_from(&rest[offset..offset + 64])
                .map_err(|_| Error::InvalidFormat)?;
            auth_chain.push(sig).map_err(|_| Error::TooManySignatures)?;
            offset += 64;
        }

        Ok(Self {
            header,
            path,
            content,
            auth_chain,
        })
    }

    /// Convert packet to bytes
    pub fn to_bytes(&self) -> Result<HVec<u8, 2048>, Error> {
        let mut bytes = HVec::new();

        // Write header
        bytes
            .extend_from_slice(self.header.as_bytes())
            .map_err(|_| Error::PacketTooLarge)?;

        // Write path vector
        for hop in &self.path.hops {
            bytes
                .extend_from_slice(hop)
                .map_err(|_| Error::PacketTooLarge)?;
        }

        for sig in &self.path.signatures {
            bytes
                .extend_from_slice(sig)
                .map_err(|_| Error::PacketTooLarge)?;
        }

        // Write content
        bytes
            .extend_from_slice(&self.content)
            .map_err(|_| Error::PacketTooLarge)?;

        // Write auth chain
        for sig in &self.auth_chain {
            bytes
                .extend_from_slice(sig)
                .map_err(|_| Error::PacketTooLarge)?;
        }

        Ok(bytes)
    }

    // Getters
    pub fn source(&self) -> PublicKey {
        self.header.source
    }
    pub fn destination(&self) -> PublicKey {
        self.header.destination
    }
    pub fn content(&self) -> &[u8] {
        &self.content
    }
    pub fn auth_chain(&self) -> &[Signature] {
        &self.auth_chain
    }
    pub fn path(&self) -> &PathVector {
        &self.path
    }
    pub fn path_mut(&mut self) -> &mut PathVector {
        &mut self.path
    }
}

/// Validated packet ready for processing
#[derive(Debug)]
pub struct TrustedPacket {
    inner: Packet,
}

impl TrustedPacket {
    /// Create new trusted packet (should only be called after validation)
    pub(crate) fn new(packet: Packet) -> Self {
        Self { inner: packet }
    }

    // Delegate getters to inner packet
    pub fn content(&self) -> &[u8] {
        self.inner.content()
    }
    pub fn source(&self) -> PublicKey {
        self.inner.source()
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidMagic,
    InvalidFormat,
    PacketTooLarge,
    TooManyHops,
    TooManySignatures,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let content = b"Hello, mesh!";
        let source = [1u8; 32];
        let dest = [2u8; 32];

        let packet = Packet::new(source, dest, content).unwrap();
        let bytes = packet.to_bytes().unwrap();
        let parsed = Packet::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.content(), content);
        assert_eq!(parsed.source(), source);
        assert_eq!(parsed.destination(), dest);
    }
}
