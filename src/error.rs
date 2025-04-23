use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MacTelnetError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Invalid MAC address: {0}")]
    InvalidMac(String),

    #[error("Failed to retransmit packet after all retries")]
    RetransmitFailed,

    #[error("Terminal error: {0}")]
    Terminal(String),

    #[error("Packet too large: {0} bytes")]
    PacketTooLarge(usize),
}

impl MacTelnetError {
    pub fn is_network_error(&self) -> bool {
        matches!(
            self,
            MacTelnetError::Network(_)
                | MacTelnetError::InvalidPacket(_)
                | MacTelnetError::PacketTooLarge(_)
                | MacTelnetError::IoError(_)
        )
    }
}
