// error.rs
#![no_std]

/// Core error type for mesh network operations
#[derive(Debug)]
pub enum Error {
    /// Packet-related errors
    Packet(PacketError),

    /// Authorization-related errors
    Auth(AuthError),

    /// Routing-related errors
    Routing(RoutingError),

    /// Transmission-related errors
    Transmit(TransmitError),
}

/// Specific packet validation errors
#[derive(Debug)]
pub enum PacketError {
    /// Invalid magic bytes
    InvalidMagic,
    /// Packet too large
    SizeExceeded,
    /// Invalid format/structure
    InvalidFormat,
    /// Too many hops in path
    TooManyHops,
    /// Too many signatures
    TooManySignatures,
    /// Invalid packet version
    InvalidVersion,
    /// Content too large
    ContentTooLarge,
}

/// Authorization-related errors
#[derive(Debug)]
pub enum AuthError {
    /// Invalid signature
    InvalidSignature,
    /// Expired rights
    RightsExpired,
    /// Insufficient rights
    InsufficientRights,
    /// Invalid rights delegation
    InvalidDelegation,
    /// Too many delegations
    TooManyDelegations,
    /// Invalid authorization chain
    InvalidChain,
}

/// Routing-related errors
#[derive(Debug)]
pub enum RoutingError {
    /// No route to destination
    NoRoute,
    /// Invalid path vector
    InvalidPath,
    /// Path too long
    PathTooLong,
    /// Invalid route update
    InvalidUpdate,
    /// Route table full
    TableFull,
}

/// Transmission-related errors
#[derive(Debug)]
pub enum TransmitError {
    /// Transmission buffer full
    BufferFull,
    /// Transmission failed
    SendFailed,
    /// Invalid transmission state
    InvalidState,
}

/// Result type alias for mesh network operations
pub type Result<T> = core::result::Result<T, Error>;

impl From<PacketError> for Error {
    fn from(error: PacketError) -> Self {
        Error::Packet(error)
    }
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        Error::Auth(error)
    }
}

impl From<RoutingError> for Error {
    fn from(error: RoutingError) -> Self {
        Error::Routing(error)
    }
}

impl From<TransmitError> for Error {
    fn from(error: TransmitError) -> Self {
        Error::Transmit(error)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Packet(e) => write!(f, "Packet error: {:?}", e),
            Error::Auth(e) => write!(f, "Authorization error: {:?}", e),
            Error::Routing(e) => write!(f, "Routing error: {:?}", e),
            Error::Transmit(e) => write!(f, "Transmission error: {:?}", e),
        }
    }
}

/// Helper functions for creating specific errors
impl Error {
    pub fn packet_too_large() -> Self {
        Error::Packet(PacketError::SizeExceeded)
    }

    pub fn invalid_signature() -> Self {
        Error::Auth(AuthError::InvalidSignature)
    }

    pub fn no_route() -> Self {
        Error::Routing(RoutingError::NoRoute)
    }

    pub fn transmit_failed() -> Self {
        Error::Transmit(TransmitError::SendFailed)
    }
}

/// Additional context methods
impl Error {
    /// Check if error is related to packet validation
    pub fn is_packet_error(&self) -> bool {
        matches!(self, Error::Packet(_))
    }

    /// Check if error is related to authorization
    pub fn is_auth_error(&self) -> bool {
        matches!(self, Error::Auth(_))
    }

    /// Check if error is related to routing
    pub fn is_routing_error(&self) -> bool {
        matches!(self, Error::Routing(_))
    }

    /// Check if error is related to transmission
    pub fn is_transmit_error(&self) -> bool {
        matches!(self, Error::Transmit(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion() {
        let err = Error::from(PacketError::SizeExceeded);
        assert!(err.is_packet_error());

        let err = Error::from(AuthError::RightsExpired);
        assert!(err.is_auth_error());
    }

    #[test]
    fn test_helper_functions() {
        let err = Error::packet_too_large();
        assert!(err.is_packet_error());

        let err = Error::no_route();
        assert!(err.is_routing_error());
    }
}
