// src/packet.rs
use crate::error::MeshError;
use zerocopy::{AsBytes, FromBytes, Unaligned};

/// Magic bytes that every valid packet must start with ("MESH")
pub const PACKET_MAGIC: [u8; 4] = [0x4D, 0x45, 0x53, 0x48];

/// Different types of packets in the mesh network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    Data = 0,
    Control = 1,
    Discovery = 2,
    Error = 255,
}

impl TryFrom<u8> for PacketType {
    type Error = MeshError;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0 => Ok(PacketType::Data),
            1 => Ok(PacketType::Control),
            2 => Ok(PacketType::Discovery),
            255 => Ok(PacketType::Error),
            _ => Err(MeshError::PacketError(format!(
                "Invalid packet type: {}",
                value
            ))),
        }
    }
}

/// Raw packet header that can be safely zero-copied from bytes
///
/// # Payload Size Decision
/// Currently using u32 for payload_length which allows payloads up to ~4GB.
/// This decision balances several factors:
/// - Modern use cases like file transfer, media sharing, and blockchain data often exceed 65KB
/// - Network capabilities (5G, fiber) can handle multi-MB packets
/// - Keeps implementation simple compared to packet fragmentation
///
/// # Future Considerations
/// We may need to implement packet fragmentation if we find:
/// - Network reliability issues with large packets
/// - Memory constraints on some mesh nodes
/// - Need for progress tracking on large transfers
/// - MTU limitations causing excessive fragmentation at transport layer
///
/// For now, the simpler u32 approach lets us validate the design while keeping the codebase
/// maintainable. Monitor real-world usage patterns to inform future fragmentation needs.
#[derive(Debug, FromBytes, AsBytes, Unaligned, Clone)]
#[repr(C, packed)]
pub struct PacketHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub packet_type: u8,
    pub payload_length: u32,
    pub source_id: [u8; 32],
    pub destination_id: [u8; 32],
    pub nonce: [u8; 8],
}

impl PacketHeader {
    /// Validates the basic structure of the header
    pub fn validate(&self) -> Result<(), MeshError> {
        // Check magic bytes
        if self.magic != PACKET_MAGIC {
            return Err(MeshError::PacketError("Invalid magic bytes".to_string()));
        }

        // Check version
        if self.version != 1 {
            return Err(MeshError::PacketError(format!(
                "Unsupported version: {}",
                self.version
            )));
        }

        // Validate packet type
        PacketType::try_from(self.packet_type)?;

        Ok(())
    }
}

impl AsRef<[u8]> for PacketHeader {
    fn as_ref(&self) -> &[u8] {
        // Convert the header to its byte representation
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

/// A packet that hasn't been validated yet
#[derive(Debug, Clone)]
pub struct UntrustedPacket {
    header: PacketHeader,
    payload: Vec<u8>,
    signature: [u8; 64], // Ed25519 signatures are 64 bytes
}

impl UntrustedPacket {
    /// Attempts to parse an untrusted packet from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MeshError> {
        // Ensure we have enough bytes for the header
        if bytes.len() < std::mem::size_of::<PacketHeader>() {
            return Err(MeshError::PacketError(
                "Packet too short for header".to_string(),
            ));
        }

        // Parse header using zerocopy
        let (header, rest) =
            match zerocopy::LayoutVerified::<&[u8], PacketHeader>::new_unaligned_from_prefix(bytes)
            {
                Some((header, rest)) => (header.to_owned(), rest),
                None => return Err(MeshError::PacketError("Failed to parse header".to_string())),
            };

        // Validate the header immediately after parsing
        header.validate()?; // Add this line!

        // Rest of the implementation...
        let payload_len = header.payload_length as usize;
        if rest.len() < payload_len + 64 {
            return Err(MeshError::PacketError(
                "Packet too short for payload and signature".to_string(),
            ));
        }

        // Extract payload and signature
        let payload = rest[..payload_len].to_vec();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&rest[payload_len..payload_len + 64]);

        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    /// Gets a reference to the header
    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    /// Gets a reference to the payload
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Gets a reference to the signature
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// A packet that has been validated and is safe to process
#[derive(Debug)]
pub struct TrustedPacket {
    inner: UntrustedPacket,
    validated_at: std::time::SystemTime,
}

impl TrustedPacket {
    /// Creates a new trusted packet from an untrusted one
    /// This should only be called after proper validation
    pub(crate) fn from_untrusted(packet: UntrustedPacket) -> Self {
        Self {
            inner: packet,
            validated_at: std::time::SystemTime::now(),
        }
    }

    /// Gets a reference to the header
    pub fn header(&self) -> &PacketHeader {
        &self.inner.header
    }

    /// Gets a reference to the payload
    pub fn payload(&self) -> &[u8] {
        &self.inner.payload
    }

    /// Gets when this packet was validated
    pub fn validated_at(&self) -> std::time::SystemTime {
        self.validated_at
    }
}
