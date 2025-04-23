use crate::packet::PacketType;
use crate::packet::PROTOCOL_VERSION;
use byteorder::{BigEndian, ByteOrder};

const CLIENT_TYPE: u16 = 0x0015;

/// MAC-Telnet header structure
/// Format:
/// 0     1     2         8         14        18       22
/// +-----+-----+---------+---------+---------+---------+
/// | ver |ptype| srcaddr               | dstaddr       |
/// +-----+-----+---------+---------+---------+---------+
/// | seskey       | counter       | variable data      |
/// +--------------+---------------+--------------------+
#[derive(Debug, Clone)]
pub struct Header {
    pub ver: u8,
    pub ptype: PacketType,
    pub srcaddr: [u8; 6],
    pub dstaddr: [u8; 6],
    pub seskey: u32,
    pub counter: u32,
    is_server: bool,
}

impl Header {
    pub fn new(
        srcaddr: [u8; 6],
        dstaddr: [u8; 6],
        ptype: PacketType,
        seskey: u32,
        counter: u32,
        is_server: bool,
    ) -> Self {
        Header {
            ver: PROTOCOL_VERSION,
            ptype,
            srcaddr,
            dstaddr,
            seskey,
            counter,
            is_server,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(22);
        bytes.push(self.ver);
        bytes.push(self.ptype as u8);
        bytes.extend_from_slice(&self.srcaddr);
        bytes.extend_from_slice(&self.dstaddr);

        // Handle session key endianness based on packet direction
        let seskey_bytes = if self.is_server {
            // Server packets: 0x0015abcd
            ((CLIENT_TYPE as u32) << 16 | (self.seskey & 0xFFFF)).to_be_bytes()
        } else {
            // Client packets: 0xabcd0015
            ((self.seskey & 0xFFFF) << 16 | CLIENT_TYPE as u32).to_be_bytes()
        };
        bytes.extend_from_slice(&seskey_bytes);

        bytes.extend_from_slice(&self.counter.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8], is_server: bool) -> Option<Self> {
        if bytes.len() < 22 {
            return None;
        }

        let mut srcaddr = [0u8; 6];
        let mut dstaddr = [0u8; 6];

        srcaddr.copy_from_slice(&bytes[2..8]);
        dstaddr.copy_from_slice(&bytes[8..14]);

        let raw_seskey = BigEndian::read_u32(&bytes[14..18]);
        let seskey = if is_server {
            // For server packets: 0x0015abcd -> 0xabcd
            raw_seskey & 0xFFFF
        } else {
            // For client packets: 0xabcd0015 -> 0xabcd
            (raw_seskey >> 16) & 0xFFFF
        };

        Some(Header {
            ver: bytes[0],
            ptype: bytes[1].into(),
            srcaddr,
            dstaddr,
            seskey,
            counter: BigEndian::read_u32(&bytes[18..22]),
            is_server,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_header(is_server: bool) -> Header {
        Header::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], // source MAC
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // destination MAC
            PacketType::Data,
            0xABCD, // client key
            0,      // counter
            is_server,
        )
    }

    #[test]
    fn test_client_header_seskey_format() {
        let header = create_test_header(false);
        let bytes = header.to_bytes();

        // Client packets should have format 0xABCD0015
        assert_eq!(&bytes[14..18], &[0xAB, 0xCD, 0x00, 0x15]);
    }

    #[test]
    fn test_server_header_seskey_format() {
        let header = create_test_header(true);
        let bytes = header.to_bytes();

        // Server packets should have format 0x0015ABCD
        assert_eq!(&bytes[14..18], &[0x00, 0x15, 0xAB, 0xCD]);
    }

    #[test]
    fn test_header_version() {
        let header = create_test_header(false);
        let bytes = header.to_bytes();
        assert_eq!(bytes[0], PROTOCOL_VERSION);
    }

    #[test]
    fn test_header_macs() {
        let header = create_test_header(false);
        let bytes = header.to_bytes();

        assert_eq!(&bytes[2..8], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&bytes[8..14], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_header_counter() {
        let header = Header::new([0; 6], [0; 6], PacketType::Data, 0, 0x12345678, false);
        let bytes = header.to_bytes();
        assert_eq!(&bytes[18..22], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_header_roundtrip() {
        let original = create_test_header(false);
        let bytes = original.to_bytes();
        let parsed = Header::from_bytes(&bytes, false).unwrap();

        assert_eq!(parsed.ver, original.ver);
        assert_eq!(parsed.ptype, original.ptype);
        assert_eq!(parsed.srcaddr, original.srcaddr);
        assert_eq!(parsed.dstaddr, original.dstaddr);
        assert_eq!(parsed.seskey, original.seskey);
        assert_eq!(parsed.counter, original.counter);
    }

    #[test]
    fn test_invalid_header_size() {
        assert!(Header::from_bytes(&[0; 21], false).is_none());
    }

    #[test]
    fn test_header_creation() {
        let header = Header::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            PacketType::Data,
            0x12345678,
            0x87654321,
            false,
        );

        assert_eq!(header.srcaddr, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(header.dstaddr, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(header.ptype, PacketType::Data);
        assert_eq!(header.seskey, 0x12345678);
        assert_eq!(header.counter, 0x87654321);
    }

    #[test]
    fn test_header_serialization() {
        let header = Header::new(
            [0x12, 0x34, 0x56, 0x78, 0x00, 0x15],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            PacketType::Data,
            0x5678, // Only 16 bits are used
            0x87654321,
            false,
        );
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), 22);
        assert_eq!(&bytes[2..8], &[0x12, 0x34, 0x56, 0x78, 0x00, 0x15]);
        assert_eq!(&bytes[8..14], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(bytes[1], PacketType::Data as u8);
        // For client packets: [key][type] -> 0x56780015
        assert_eq!(&bytes[14..18], &[0x56, 0x78, 0x00, 0x15]);
        assert_eq!(&bytes[18..22], &[0x87, 0x65, 0x43, 0x21]);

        // Verify we can deserialize it back correctly
        let parsed = Header::from_bytes(&bytes, false).unwrap();
        assert_eq!(parsed.seskey, 0x5678);
    }

    #[test]
    fn test_header_deserialization() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src_mac
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dst_mac
            0x02, // version
            0x00, // ptype
            0x12, 0x34, 0x56, 0x78, // seskey
            0x00, 0x00, 0x00, 0x01, // counter
        ];

        let header = Header::from_bytes(&bytes, false).unwrap();
        assert_eq!(header.srcaddr, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(header.dstaddr, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(header.ver, 2);
        assert_eq!(header.ptype, PacketType::Start);
        assert_eq!(header.seskey, 0x1234);
        assert_eq!(header.counter, 1);
    }

    #[test]
    fn test_header_packet_type_conversion() {
        let mut bytes = vec![0; 22];
        bytes[0] = PROTOCOL_VERSION;
        bytes[1] = PacketType::Start as u8;

        let header = Header::from_bytes(&bytes, false).unwrap();
        assert_eq!(header.ptype, PacketType::Start);
    }

    #[test]
    fn test_header_endianness() {
        let header = Header::new(
            [0; 6],
            [0; 6],
            PacketType::Data,
            0x5678, // Only 16 bits are used
            0x87654321,
            false,
        );

        let bytes = header.to_bytes();

        // For client packets: [key][type]
        assert_eq!(&bytes[14..18], &[0x56, 0x78, 0x00, 0x15]);
        assert_eq!(&bytes[18..22], &[0x87, 0x65, 0x43, 0x21]); // counter
    }
}
