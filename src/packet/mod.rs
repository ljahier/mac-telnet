pub mod control;
pub mod header;

pub use control::{ControlPacket, ControlPacketType};
pub use header::Header;

pub const MAC_TELNET_PORT: u16 = 20561;
pub const PROTOCOL_VERSION: u8 = 0x01;
pub const CONTROL_PACKET_MAGIC: [u8; 4] = [0x56, 0x34, 0x12, 0xFF];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Start = 0,
    Data = 1,
    Ack = 2,
    Timeout = 3,
    Discovery = 4,
    DiscoveryResponse = 5,
    End = 255,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => PacketType::Start,
            1 => PacketType::Data,
            2 => PacketType::Ack,
            3 => PacketType::Timeout,
            4 => PacketType::Discovery,
            5 => PacketType::DiscoveryResponse,
            255 => PacketType::End,
            _ => PacketType::End,
        }
    }
}
