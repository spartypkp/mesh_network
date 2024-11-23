# lib.rs Core Specification

## Module Structure
```rust
// External dependencies
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use zerocopy::{AsBytes, FromBytes};

// Internal modules
mod auth;
mod error;
mod packet;

// Re-exports for public API
pub use auth::{Rights, AuthTree};
pub use error::Error;
pub use packet::{Packet, PathVector};
```

## Transmitter Trait
```rust
/// Abstract interface for sending bytes
pub trait Transmitter {
    /// Send bytes over the network
    fn transmit(&mut self, bytes: &[u8]) -> Result<(), Error>;
    
    /// Check if transmission is possible
    fn can_transmit(&self) -> bool;
}
```

## Core Types

### Network Structure
```rust
pub struct Network<T: Transmitter> {
    /// Network's keypair
    keypair: Ed25519KeyPair,
    
    /// Network's public key
    network_key: PublicKey,
    
    /// Byte transmitter implementation
    transmitter: T,
    
    /// Optional routing table (None for non-routing nodes)
    routes: Option<RouteTable>,
    
    /// Authorization tree
    auth: AuthTree,
}
```

### Route Table
```rust
struct RouteTable {
    /// Full path vectors for routing nodes
    paths: HashMap<PublicKey, PathVector>,
    
    /// Next hop for non-routing nodes
    next_hop: Option<PublicKey>,
}
```

## Core Functions

### Construction
```rust
impl<T: Transmitter> Network<T> {
    /// Create new network instance
    pub fn new(
        transmitter: T,
        keypair: Ed25519KeyPair,
        network_key: PublicKey,
        is_router: bool,
    ) -> Self;
}
```

### Packet Processing
```rust
impl<T: Transmitter> Network<T> {
    /// Process incoming packets
    /// Returns Some(TrustedPacket) if valid and meant for us
    /// Returns None if invalid or needs forwarding
    pub fn accept(&mut self, bytes: &[u8]) -> Option<TrustedPacket>;

    /// Send message to destination
    pub fn send(
        &mut self,
        destination: PublicKey,
        content: &[u8]
    ) -> Result<(), Error>;
}
```

### Route Management
```rust
impl<T: Transmitter> Network<T> {
    /// Update routing table with new information
    pub fn update_routes(&mut self, update: RouteUpdate) -> Result<(), Error>;
    
    /// Get next hop for destination
    fn get_next_hop(&self, dest: &PublicKey) -> Option<PublicKey>;
}
```

### Authorization
```rust
impl<T: Transmitter> Network<T> {
    /// Verify authorization chain
    fn verify_auth(&self, chain: &[Signature]) -> bool;
    
    /// Delegate rights to another node
    pub fn delegate_rights(
        &self,
        to: PublicKey,
        rights: Rights,
        ttl: Duration,
    ) -> Result<Signature, Error>;
}
```

## Helper Functions
```rust
impl<T: Transmitter> Network<T> {
    /// Forward packet to next hop
    fn forward_packet(&mut self, packet: &Packet) -> Result<(), Error>;
    
    /// Process locally destined packet
    fn process_local(&self, packet: Packet) -> Option<TrustedPacket>;
    
    /// Verify and truncate path vector
    fn handle_path(&mut self, packet: &mut Packet) -> Result<(), Error>;
}
```

## Type Aliases
```rust
type PublicKey = [u8; 32];
type Signature = [u8; 64];
type RouteUpdate = (PublicKey, PathVector, Vec<Signature>);
```

## Error Handling
- Use `Result<T, Error>` for operations that can fail
- Use `Option<T>` for operations that might not produce a value
- Minimize error variants and keep messages simple

## Key Behaviors

1. **Packet Reception**:
   - Parse and validate incoming bytes
   - Verify authorization chain
   - Process or forward based on destination
   - Handle path truncation for routing nodes

2. **Message Sending**:
   - Create new packet with auth chain
   - Compute path vector (if routing node)
   - Encrypt content for destination
   - Transmit using abstract transmitter

3. **Route Updates**:
   - Verify update authorization
   - Apply CRDT merge rules
   - Update local route table
   - Propagate if necessary

4. **Authorization**:
   - Verify signature chains
   - Check TTLs
   - Validate routing rights
   - Handle rights delegation

This specification focuses on:
- Clear separation of concerns
- Simple, focused interfaces
- Essential functionality only
- Type safety and validation

Would you like me to:
1. Detail any specific component further?
2. Add more behavioral specifications?
3. Expand on the CRDT update logic?
4. Something else?

Once we're satisfied with this specification, we can move on to implementation.