use crate::packet::CONTROL_PACKET_MAGIC;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPacketType {
    BeginAuth = 0,     // Client -> Server: Start authentication
    EncryptionKey = 1, // Server -> Client: Send encryption key
    Password = 2,      // Client -> Server: Send password
    Username = 3,      // Client -> Server: Send username
    TerminalType = 4,  // Client -> Server: Terminal type
    Width = 5,         // Client -> Server: Terminal width
    Height = 6,        // Client -> Server: Terminal height
    Invalid = 7,       // Invalid/Unknown packet
    EndAuth = 9,       // Server -> Client: End authentication
}

impl From<u8> for ControlPacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => ControlPacketType::BeginAuth,
            1 => ControlPacketType::EncryptionKey,
            2 => ControlPacketType::Password,
            3 => ControlPacketType::Username,
            4 => ControlPacketType::TerminalType,
            5 => ControlPacketType::Width,
            6 => ControlPacketType::Height,
            7 => ControlPacketType::Invalid,
            9 => ControlPacketType::EndAuth,
            _ => ControlPacketType::Invalid,
        }
    }
}

/// Control packet structure
/// Format:
/// 4B magic | 1B type | 4B length | payload[length]
#[derive(Debug, Clone)]
pub struct ControlPacket {
    /// Control packet type
    pub ctype: ControlPacketType,
    /// Packet data
    pub payload: Vec<u8>,
}

impl ControlPacket {
    pub fn new(ctype: ControlPacketType, payload: Vec<u8>) -> Self {
        ControlPacket { ctype, payload }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9 + self.payload.len());
        bytes.extend_from_slice(&CONTROL_PACKET_MAGIC);
        bytes.push(self.ctype as u8);

        let mut len_bytes = [0u8; 4];
        BigEndian::write_u32(&mut len_bytes, self.payload.len() as u32);
        bytes.extend_from_slice(&len_bytes);
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 || &bytes[0..4] != CONTROL_PACKET_MAGIC {
            return None;
        }

        let ctype = bytes[4].into();
        let length = BigEndian::read_u32(&bytes[5..9]) as usize;

        if bytes.len() < 9 + length {
            return None;
        }

        let payload = bytes[9..9 + length].to_vec();
        Some(ControlPacket { ctype, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_begin_auth_packet() {
        let packet = ControlPacket::new(ControlPacketType::BeginAuth, Vec::new());
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], CONTROL_PACKET_MAGIC);
        assert_eq!(bytes[4], 0); // BeginAuth type = 0
        assert_eq!(&bytes[5..9], &[0, 0, 0, 0]); // Empty payload = 0 length
    }

    #[test]
    fn test_encryption_key_packet() {
        let key_data = [1u8; 32]; // Example encryption key
        let packet = ControlPacket::new(ControlPacketType::EncryptionKey, key_data.to_vec());
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], CONTROL_PACKET_MAGIC);
        assert_eq!(bytes[4], 1); // EncryptionKey type = 1
        assert_eq!(&bytes[5..9], &[0, 0, 0, 32]); // Length = 32
        assert_eq!(&bytes[9..], &key_data);
    }

    #[test]
    fn test_password_packet() {
        let password_data = b"test_password";
        let packet = ControlPacket::new(ControlPacketType::Password, password_data.to_vec());
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], CONTROL_PACKET_MAGIC);
        assert_eq!(bytes[4], 2); // Password type = 2
        assert_eq!(&bytes[5..9], &[0, 0, 0, 13]); // Length = 13 (test_password is 13 bytes)
        assert_eq!(&bytes[9..], password_data);
    }

    #[test]
    fn test_username_packet() {
        let username = b"admin";
        let packet = ControlPacket::new(ControlPacketType::Username, username.to_vec());
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], CONTROL_PACKET_MAGIC);
        assert_eq!(bytes[4], 3); // Username type = 3
        assert_eq!(&bytes[5..9], &[0, 0, 0, 5]); // Length = 5
        assert_eq!(&bytes[9..], username);
    }

    #[test]
    fn test_terminal_size_packets() {
        let width: u16 = 80;
        let height: u16 = 24;

        let width_packet =
            ControlPacket::new(ControlPacketType::Width, width.to_be_bytes().to_vec());
        let height_packet =
            ControlPacket::new(ControlPacketType::Height, height.to_be_bytes().to_vec());

        let width_bytes = width_packet.to_bytes();
        let height_bytes = height_packet.to_bytes();

        // Test width packet
        assert_eq!(width_bytes[4], 5); // Width type = 5
        assert_eq!(&width_bytes[9..11], &[0, 80]); // Width = 80

        // Test height packet
        assert_eq!(height_bytes[4], 6); // Height type = 6
        assert_eq!(&height_bytes[9..11], &[0, 24]); // Height = 24
    }

    #[test]
    fn test_end_auth_packet() {
        let packet = ControlPacket::new(ControlPacketType::EndAuth, Vec::new());
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], CONTROL_PACKET_MAGIC);
        assert_eq!(bytes[4], 9); // EndAuth type = 9
        assert_eq!(&bytes[5..9], &[0, 0, 0, 0]); // Empty payload
    }

    #[test]
    fn test_invalid_packet() {
        let packet = ControlPacket::new(ControlPacketType::Invalid, Vec::new());
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], CONTROL_PACKET_MAGIC);
        assert_eq!(bytes[4], 7); // Invalid type = 7
    }

    #[test]
    fn test_parse_invalid_magic() {
        let invalid_bytes = [0xFF; 9];
        assert!(ControlPacket::from_bytes(&invalid_bytes).is_none());
    }

    #[test]
    fn test_parse_truncated_packet() {
        let truncated = [0x56, 0x34, 0x12, 0xFF, 0x00];
        assert!(ControlPacket::from_bytes(&truncated).is_none());
    }

    #[test]
    fn test_control_packet_roundtrip() {
        let types = [
            ControlPacketType::BeginAuth,
            ControlPacketType::EncryptionKey,
            ControlPacketType::Password,
            ControlPacketType::Username,
            ControlPacketType::TerminalType,
            ControlPacketType::Width,
            ControlPacketType::Height,
            ControlPacketType::Invalid,
            ControlPacketType::EndAuth,
        ];

        for &packet_type in &types {
            let payload = vec![1, 2, 3, 4];
            let original = ControlPacket::new(packet_type, payload.clone());
            let bytes = original.to_bytes();
            let parsed = ControlPacket::from_bytes(&bytes).unwrap();

            assert_eq!(parsed.ctype, original.ctype);
            assert_eq!(parsed.payload, original.payload);
        }
    }

    #[test]
    fn test_control_packet_type_conversion() {
        assert_eq!(ControlPacketType::from(0), ControlPacketType::BeginAuth);
        assert_eq!(ControlPacketType::from(1), ControlPacketType::EncryptionKey);
        assert_eq!(ControlPacketType::from(2), ControlPacketType::Password);
        assert_eq!(ControlPacketType::from(3), ControlPacketType::Username);
        assert_eq!(ControlPacketType::from(4), ControlPacketType::TerminalType);
        assert_eq!(ControlPacketType::from(5), ControlPacketType::Width);
        assert_eq!(ControlPacketType::from(6), ControlPacketType::Height);
        assert_eq!(ControlPacketType::from(7), ControlPacketType::Invalid);
        assert_eq!(ControlPacketType::from(9), ControlPacketType::EndAuth);
    }

    #[test]
    fn test_control_packet_creation() {
        let payload = vec![1, 2, 3, 4];
        let packet = ControlPacket::new(ControlPacketType::Username, payload.clone());

        assert_eq!(packet.ctype, ControlPacketType::Username);
        assert_eq!(packet.payload, payload);
    }

    #[test]
    fn test_control_packet_serialization() {
        let payload = vec![1, 2, 3, 4];
        let packet = ControlPacket::new(ControlPacketType::Username, payload);
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[0..4], &CONTROL_PACKET_MAGIC);
        assert_eq!(bytes[4], ControlPacketType::Username as u8);
        assert_eq!(BigEndian::read_u32(&bytes[5..9]), 4);
        assert_eq!(&bytes[9..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_control_packet_deserialization() {
        let payload = vec![1, 2, 3, 4];
        let original = ControlPacket::new(ControlPacketType::Username, payload);
        let bytes = original.to_bytes();
        let parsed = ControlPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.ctype, original.ctype);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_control_packet_invalid_magic() {
        let mut bytes = vec![0; 13];
        bytes[4] = ControlPacketType::Username as u8;
        assert!(ControlPacket::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_control_packet_invalid_size() {
        let bytes = vec![
            0x56, 0x34, 0x12, 0xFF, // magic
            0x03, // Username type
            0x00, 0x00, 0x00, 0x04, // payload length = 4
            0x01, 0x02, 0x03, // only 3 bytes payload
        ];
        assert!(ControlPacket::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_control_packet_zero_payload() {
        let packet = ControlPacket::new(ControlPacketType::EndAuth, vec![]);
        let bytes = packet.to_bytes();
        let parsed = ControlPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.ctype, ControlPacketType::EndAuth);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_control_packet_large_payload() {
        let payload = vec![0xFF; 1024];
        let packet = ControlPacket::new(ControlPacketType::TerminalType, payload.clone());
        let bytes = packet.to_bytes();
        let parsed = ControlPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.ctype, ControlPacketType::TerminalType);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_control_packet_endianness() {
        // Test big-endian length field
        let payload = vec![1, 2, 3, 4];
        let packet = ControlPacket::new(ControlPacketType::Username, payload);
        let bytes = packet.to_bytes();

        assert_eq!(&bytes[5..9], &[0, 0, 0, 4]);
    }
}
