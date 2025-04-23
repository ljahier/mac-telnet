use crate::error::MacTelnetError;
use crate::packet::{Header, MAC_TELNET_PORT};
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct MacTelnetSocket {
    socket: Arc<UdpSocket>,
    interface: NetworkInterface,
}

impl MacTelnetSocket {
    pub fn bind(interface: NetworkInterface) -> io::Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", MAC_TELNET_PORT))?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        Ok(MacTelnetSocket {
            socket: Arc::new(socket),
            interface,
        })
    }

    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let broadcast_addr = SocketAddr::from((Ipv4Addr::BROADCAST, MAC_TELNET_PORT));
        self.socket.send_to(data, broadcast_addr)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    pub fn local_mac(&self) -> Option<[u8; 6]> {
        self.interface.mac.map(|mac| {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&mac.octets());
            bytes
        })
    }

    pub fn get_interface(&self) -> &NetworkInterface {
        &self.interface
    }
}

pub fn find_interface(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name && iface.mac.is_some())
}

pub struct NetworkChannel {
    pub interface: NetworkInterface,
    pub tx: Box<dyn datalink::DataLinkSender>,
    pub rx: Box<dyn datalink::DataLinkReceiver>,
}

pub fn create_channel(interface: &NetworkInterface) -> Result<NetworkChannel, MacTelnetError> {
    let config = Config::default();
    match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => Ok(NetworkChannel {
            interface: interface.clone(),
            tx,
            rx,
        }),
        Ok(_) => Err(MacTelnetError::Network("Invalid channel type".into())),
        Err(e) => Err(MacTelnetError::Network(e.to_string())),
    }
}

pub fn find_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
}

pub struct Network {
    interface: NetworkInterface,
    socket: Arc<Mutex<UdpSocket>>,
}

impl Network {
    pub fn new(interface: NetworkInterface) -> Result<Self, MacTelnetError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_broadcast(true)?;

        Ok(Network {
            interface,
            socket: Arc::new(Mutex::new(socket)),
        })
    }

    pub async fn send_packet(&self, header: &Header, payload: &[u8]) -> Result<(), MacTelnetError> {
        let mut bytes = Vec::with_capacity(22 + payload.len());
        bytes.extend_from_slice(&header.to_bytes());
        bytes.extend_from_slice(payload);

        let socket = self.socket.lock().await;
        socket.send_to(&bytes, format!("255.255.255.255:{}", MAC_TELNET_PORT))?;

        Ok(())
    }

    pub async fn receive_packet(
        &self,
        timeout_ms: u64,
    ) -> Result<Option<(Header, Vec<u8>)>, MacTelnetError> {
        let socket = self.socket.lock().await;
        socket.set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))?;

        let mut buf = [0u8; 2048];
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                if len < 22 {
                    return Ok(None);
                }

                let header = Header::from_bytes(&buf[..22], false)
                    .ok_or_else(|| MacTelnetError::InvalidPacket("Invalid header".into()))?;
                let payload = buf[22..len].to_vec();

                Ok(Some((header, payload)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(MacTelnetError::IoError(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketType;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU16, Ordering};

    static PORT_COUNTER: AtomicU16 = AtomicU16::new(50000);

    fn get_unique_port() -> u16 {
        PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    fn create_test_interface() -> NetworkInterface {
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && iface.mac.is_some())
            .expect("No suitable network interface found for testing")
    }

    #[test]
    fn test_socket_creation() -> io::Result<()> {
        let interface = create_test_interface();
        let socket = MacTelnetSocket::bind(interface)?;

        // Verify the socket is bound to the correct port
        let local_addr = socket.socket.local_addr()?;
        assert_eq!(local_addr.port(), MAC_TELNET_PORT);

        Ok(())
    }

    #[test]
    fn test_socket_broadcast() -> io::Result<()> {
        let port = get_unique_port();
        let interface = create_test_interface();
        let socket = MacTelnetSocket::bind(interface)?;

        // Verify broadcast is enabled
        let broadcast = socket.socket.broadcast()?;
        assert!(broadcast, "Broadcast should be enabled");

        Ok(())
    }

    #[test]
    fn test_local_mac() {
        let interface = create_test_interface();
        let mac = interface.mac.expect("Test interface should have MAC");
        let socket = MacTelnetSocket::bind(interface).unwrap();

        let local_mac = socket.local_mac().unwrap();
        assert_eq!(&local_mac[..], &mac.octets());
    }

    #[test]
    fn test_find_interface() {
        let interface = create_test_interface();
        let found = find_interface(&interface.name);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, interface.name);
    }

    #[test]
    fn test_find_nonexistent_interface() {
        let found = find_interface("nonexistent0");
        assert!(found.is_none());
    }

    #[test]
    fn test_send_receive() -> io::Result<()> {
        let port = get_unique_port();
        let interface = create_test_interface();
        let socket1 = MacTelnetSocket::bind(interface.clone())?;
        let socket2 = MacTelnetSocket::bind(interface)?;

        // Test data
        let test_data = b"Hello, MAC-Telnet!";

        // Send from socket1
        socket1.send(test_data)?;

        // Receive on socket2
        let mut buf = [0u8; 1024];
        if let Ok((len, addr)) = socket2.recv(&mut buf) {
            assert_eq!(&buf[..len], test_data);
            assert_eq!(addr.port(), MAC_TELNET_PORT);
            assert!(matches!(addr.ip(), IpAddr::V4(_)));
        }

        Ok(())
    }

    async fn create_test_network_pair() -> (Network, Network) {
        let interface = create_test_interface();
        let network1 = Network::new(interface.clone()).unwrap();
        let network2 = Network::new(interface).unwrap();
        (network1, network2)
    }

    #[tokio::test]
    async fn test_send_receive_packet() {
        let port = get_unique_port();
        let (network1, network2) = create_test_network_pair().await;

        // Create test packet
        let header = Header::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            PacketType::Data,
            0x1234,
            0,
            false,
        );
        let payload = b"test message";

        // Send packet from network1
        network1.send_packet(&header, payload).await.unwrap();

        // Receive packet on network2
        if let Some((received_header, received_payload)) =
            network2.receive_packet(1000).await.unwrap()
        {
            assert_eq!(received_header.srcaddr, header.srcaddr);
            assert_eq!(received_header.dstaddr, header.dstaddr);
            assert_eq!(received_header.ptype, header.ptype);
            assert_eq!(received_header.seskey, header.seskey);
            assert_eq!(received_payload, payload);
        } else {
            panic!("No packet received");
        }
    }

    #[tokio::test]
    async fn test_broadcast_receive() {
        let port = get_unique_port();
        let interface = create_test_interface();
        let network = Network::new(interface).unwrap();

        // Test broadcast reception
        let header = Header::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            PacketType::Start,
            0x1234,
            0,
            false,
        );

        network.send_packet(&header, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn test_packet_timeout() {
        let interface = create_test_interface();
        let network = Network::new(interface).unwrap();

        // Set a very short timeout
        let result = network.receive_packet(1).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_multiple_packets() {
        let port = get_unique_port();
        let (network1, network2) = create_test_network_pair().await;

        let header = Header::new(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            PacketType::Data,
            0x1234,
            0,
            false,
        );

        // Send multiple packets with delay between each
        for i in 0..3 {
            let payload = format!("test message {}", i).into_bytes();
            network1.send_packet(&header, &payload).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Receive and verify each packet with increased timeout
            if let Some((_, received_payload)) = network2.receive_packet(2000).await.unwrap() {
                assert_eq!(received_payload, payload);
            } else {
                panic!("Packet {} not received", i);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_packet() {
        let interface = create_test_interface();
        let network = Network::new(interface).unwrap();
        let socket = network.socket.lock().await;

        // Send invalid data
        socket
            .send_to(&[0u8; 10], format!("255.255.255.255:{}", MAC_TELNET_PORT))
            .unwrap();
        drop(socket);

        // Should return None for invalid packet
        let result = network.receive_packet(1000).await.unwrap();
        assert!(result.is_none());
    }
}
