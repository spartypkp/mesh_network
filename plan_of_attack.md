# Mesh Network Radio Packet Validator
## System Overview & Design Document

### Purpose
This project implements a secure radio packet validation system for mesh networks. It processes untrusted radio signals, validates them using cryptographic signatures, and either forwards or processes them based on validation results.

### System Architecture
```mermaid
graph TD
    A[Radio Signal Input] --> B[Packet Parser]
    B --> C{Validation Pipeline}
    C -->|Invalid| D[Reject Packet]
    C -->|Valid| E[Process Packet]
    C -->|Valid + Forward| F[Forward to Network]
    
    subgraph Validation Pipeline
        G[Parse Header] --> H[Verify Format]
        H --> I[Verify Signature]
        I --> J[Check Source]
        J --> K[Validate Content]
    end
    
    subgraph Security Layer
        L[Ring Crypto] --> I
        M[Trusted Peers] --> J
        N[ZeroCopy Parser] --> G
    end
```

### Directory Structure
```
mesh_network/
├── Cargo.toml              # Project dependencies and metadata
├── README.md              # Project documentation
├── src/
│   ├── lib.rs            # Library entry point and public API
│   ├── crypto.rs         # Cryptographic operations
│   ├── error.rs          # Error type definitions
│   ├── network.rs        # Network management
│   ├── packet.rs         # Packet structures and parsing
│   └── state.rs          # Validation state machine
├── examples/
│   └── basic_usage.rs    # Usage examples
└── tests/
    └── integration_tests.rs
```

### Core Components

#### 1. Packet Processing (`packet.rs`)
- **Purpose**: Defines packet structures and handles parsing
- **Key Components**:
  - `PacketHeader`: Raw packet structure using zerocopy
  - `TrustedPacket`: Validated packet wrapper
  - `UntrustedPacket`: Unvalidated packet wrapper
- **Data Flow**:
  1. Raw bytes → UntrustedPacket
  2. Validation
  3. UntrustedPacket → TrustedPacket

#### 2. Validation State Machine (`state.rs`)
- **Purpose**: Manages packet validation flow
- **States**:
  - `New`: Initial state
  - `HeaderVerified`: Basic structure verified
  - `SignatureVerified`: Cryptographic validation complete
  - `Complete`: Fully validated
  - `Invalid`: Failed validation
- **Transitions**: Defined by `step()` function

#### 3. Cryptographic Layer (`crypto.rs`)
- **Purpose**: Handles cryptographic operations
- **Features**:
  - Ed25519 signature verification
  - Key management
  - Secure packet signing
- **Using**: ring crate for cryptographic operations

#### 4. Network Management (`network.rs`)
- **Purpose**: Manages network-level operations
- **Features**:
  - Peer management
  - Trusted node verification
  - Packet forwarding logic

#### 5. Error Handling (`error.rs`)
- **Purpose**: Centralized error definitions
- **Categories**:
  - Validation errors
  - Cryptographic errors
  - Network errors
  - Packet formatting errors

### Security Considerations
1. **Packet Validation**:
   - Magic byte verification
   - Version compatibility
   - Length validation
   - Signature verification
   - Source verification

2. **Cryptographic Security**:
   - Ed25519 signatures
   - Replay attack prevention
   - Nonce validation

3. **Network Security**:
   - Trusted peer verification
   - Packet forwarding rules
   - Rate limiting (planned)

### Implementation Plan

#### Phase 1: Core Infrastructure ✓
- [x] Project setup
- [x] Basic type definitions
- [x] Error handling
- [x] Basic packet parsing

#### Phase 2: Validation Pipeline (In Progress)
- [x] Header validation
- [x] Signature verification
- [x] State machine implementation
- [ ] Basic tests

#### Phase 3: Network Layer
- [ ] Peer management
- [ ] Packet forwarding
- [ ] Network tests
- [ ] Integration tests

#### Phase 4: Security Hardening
- [ ] Rate limiting
- [ ] Replay attack prevention
- [ ] Advanced validation rules
- [ ] Security tests

#### Phase 5: Optimization & Documentation
- [ ] Performance optimization
- [ ] API documentation
- [ ] Usage examples
- [ ] Benchmarking


### Implemented Components

#### 1. Packet Processing (`packet.rs`) ✓
- **Status**: Completed
- **Key Implementations**:
  - `PacketHeader`: Implemented with zerocopy for efficient parsing
  - `PacketType` enum with Data, Control, Discovery, and Error variants
  - `UntrustedPacket` with from_bytes parsing
  - `TrustedPacket` with validation timestamp
  - Comprehensive error handling
  - Initial test coverage for packet parsing

#### 2. Validation State Machine (`state.rs`) ✓
- **Status**: Completed
- **Implemented States**:
  - New → HeaderVerified → SignatureVerified → Complete
  - Invalid state with error handling
- **Features**:
  - Full Ed25519 signature verification
  - Step-by-step validation pipeline
  - Type-safe transition between untrusted and trusted packets

#### 3. Error Handling (`error.rs`) ✓
- **Status**: Completed
- **Implemented Categories**:
  - ValidationError
  - CryptoError
  - NetworkError
  - PacketError
  - ConfigError
  - InternalError
- **Features**:
  - thiserror integration
  - Ring crypto error handling

### Added Examples
1. **Packet Parsing** (`examples/packet_parsing.rs`)
   - Demonstrates packet construction
   - Shows header parsing
   - Handles payload extraction

2. **Packet Validation** (`examples/packet_validation.rs`)
   - Complete validation pipeline
   - Key pair generation
   - Signature creation and verification
   - State machine transitions

### Performance Considerations
1. Zero-copy parsing for efficient memory usage
2. State machine design for clear validation flow
3. Minimal allocations during packet processing
4. Efficient cryptographic operations

### Future Enhancements
1. Advanced packet routing
2. Dynamic peer discovery
3. Mesh network visualization
4. Performance metrics
5. Configuration API
6. Logging system

### Development Guidelines
1. All public APIs must be documented
2. Tests required for new features
3. Error handling must be comprehensive
4. Security considerations must be reviewed
5. Performance impact must be considered

### Contributing
1. WillyD
2. My boi Claude.

### License
Lol