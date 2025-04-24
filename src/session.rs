use crate::auth::Authenticator;
use crate::error::MacTelnetError;
use crate::network;
use crate::packet::control::{ControlPacket, ControlPacketType};
use crate::packet::{Header, PacketType, CONTROL_PACKET_MAGIC};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;
use pnet::datalink::NetworkInterface;
use rand::prelude::*;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, info, warn};

const KEEPALIVE_INTERVAL_SEC: u64 = 10;
// According to protocol spec:
// +0, +5,000, +10,000, +20,000, +40,000, +80,000, +160,000 microseconds
const RETRANSMIT_INTERVALS_US: &[u64] = &[0, 5000, 10000, 20000, 40000, 80000, 160000];
const AUTH_RETRY_ATTEMPTS: usize = 3;
const AUTH_RETRY_DELAY_MS: u64 = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthState {
    NotAuthenticated,
    BeginAuthSent,
    UsernameSent,
    WaitingForAuthConfirmation,
    Authenticated,
}

pub struct Session {
    interface: NetworkInterface,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    channel: Option<network::NetworkChannel>,
    seskey: u32,
    counter: u32,
    authenticator: Authenticator,
    last_activity: Instant,
    auth_state: AuthState,
    password: String,
}

impl Session {
    pub fn new(
        interface: NetworkInterface,
        dst_mac: [u8; 6],
        username: String,
    ) -> Result<Self, MacTelnetError> {
        let src_mac = interface
            .mac
            .ok_or_else(|| MacTelnetError::Network("Interface has no MAC address".into()))?
            .octets();

        let mut rng = rand::rngs::ThreadRng::default();
        let client_part = rng.random::<u32>() % (u16::MAX as u32 + 1);
        let client_type: u32 = 0x0015;
        let seskey = (client_part << 16) | client_type;

        Ok(Session {
            interface,
            src_mac,
            dst_mac,
            channel: None,
            seskey,
            counter: 0,
            authenticator: Authenticator::new(username),
            last_activity: Instant::now(),
            auth_state: AuthState::NotAuthenticated,
            password: String::new(),
        })
    }

    pub fn connect(&mut self) -> Result<(), MacTelnetError> {
        let channel = network::create_channel(&self.interface)?;
        self.channel = Some(channel);
        Ok(())
    }

    pub fn send_packet(&mut self, ptype: PacketType, payload: &[u8]) -> Result<(), MacTelnetError> {
        let channel = self.channel.as_mut().ok_or_else(|| {
            MacTelnetError::Network("Session not connected. Call connect() first".into())
        })?;

        let header = Header::new(
            self.src_mac,
            self.dst_mac,
            ptype,
            self.seskey,
            self.counter,
            false,
        );

        let mut packet = Vec::with_capacity(22 + payload.len());
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(payload);

        let result = channel.tx.send_to(&packet, None);
        match result {
            Some(Ok(())) => {
                self.counter = self.counter.wrapping_add(1);
                self.last_activity = Instant::now();
                Ok(())
            }
            Some(Err(e)) => Err(MacTelnetError::Network(e.to_string())),
            None => Ok(()),
        }
    }

    pub fn receive_packet(&mut self) -> Result<Option<(Header, Vec<u8>)>, MacTelnetError> {
        let channel = self.channel.as_mut().ok_or_else(|| {
            MacTelnetError::Network("Session not connected. Call connect() first".into())
        })?;

        match channel.rx.next() {
            Ok(packet) => {
                if packet.len() < 22 {
                    debug!("Received packet too short: {} bytes", packet.len());
                    return Ok(None);
                }

                if let Some(header) = Header::from_bytes(&packet[0..22], true) {
                    let payload = packet[22..].to_vec();
                    debug!(
                        "Received packet: type={:?}, srcMAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, counter={}",
                        header.ptype,
                        header.srcaddr[0], header.srcaddr[1], header.srcaddr[2],
                        header.srcaddr[3], header.srcaddr[4], header.srcaddr[5],
                        header.counter
                    );
                    return Ok(Some((header, payload)));
                } else {
                    debug!("Failed to parse header from packet");
                }
                Ok(None)
            }
            Err(e) => Err(MacTelnetError::Network(e.to_string())),
        }
    }

    fn is_packet_for_me(&self, header: &Header) -> bool {
        // Check if packet is destined for our MAC address
        if header.dstaddr != self.src_mac {
            debug!(
                "Packet not for us: dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, our={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                header.dstaddr[0], header.dstaddr[1], header.dstaddr[2], header.dstaddr[3], header.dstaddr[4], header.dstaddr[5],
                self.src_mac[0], self.src_mac[1], self.src_mac[2], self.src_mac[3], self.src_mac[4], self.src_mac[5]
            );
            return false;
        }

        // Before authentication, accept packets from the router MAC we're connecting to
        if self.auth_state != AuthState::Authenticated {
            let matches = header.srcaddr == self.dst_mac;
            if !matches {
                debug!(
                    "Packet source MAC not matching target router: src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, router={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    header.srcaddr[0], header.srcaddr[1], header.srcaddr[2], header.srcaddr[3], header.srcaddr[4], header.srcaddr[5],
                    self.dst_mac[0], self.dst_mac[1], self.dst_mac[2], self.dst_mac[3], self.dst_mac[4], self.dst_mac[5]
                );
            }
            return matches;
        }

        // After authentication, check both MAC and session key
        let mac_matches = header.srcaddr == self.dst_mac;
        let key_matches = header.seskey == self.seskey;

        if !mac_matches || !key_matches {
            debug!(
                "Authenticated packet validation: srcMAC_match={}, seskey_match={} (got=0x{:x}, expected=0x{:x})",
                mac_matches, key_matches, header.seskey, self.seskey
            );
        }

        mac_matches && key_matches
    }

    fn extract_control_packet(&self, payload: &[u8]) -> Option<ControlPacket> {
        if payload.len() < 9 || payload[0..4] != CONTROL_PACKET_MAGIC {
            return None;
        }

        ControlPacket::from_bytes(payload)
    }

    pub async fn run(&mut self) -> Result<(), MacTelnetError> {
        self.connect()?;

        print!("Password: ");
        io::stdout().flush()?;
        let mut password = String::new();
        io::stdin().read_line(&mut password)?;
        self.password = password.trim().to_string();

        info!("Starting MAC-Telnet session...");
        self.start_session().await?;

        self.authenticate().await?;

        terminal::enable_raw_mode()?;

        let result = self.terminal_loop().await;

        terminal::disable_raw_mode()?;

        let _ = self.send_packet(PacketType::End, &[]);

        result
    }

    async fn retransmit_with_intervals(
        &mut self,
        ptype: PacketType,
        payload: &[u8],
    ) -> Result<bool, MacTelnetError> {
        // Send initial packet
        self.send_packet(ptype, payload)?;

        // Try to get an ACK after each transmission with appropriate wait periods
        for delay in RETRANSMIT_INTERVALS_US {
            // Wait for the specified delay
            if *delay > 0 {
                sleep(Duration::from_micros(*delay)).await;
            }

            // Check multiple times for an ACK during this interval
            for _ in 0..5 {
                match self.receive_packet()? {
                    Some((header, _)) => {
                        // Check if it's an ACK packet and it's for us
                        if header.ptype == PacketType::Ack && self.is_packet_for_me(&header) {
                            info!("Received ACK packet with counter={}", header.counter);
                            return Ok(true);
                        }
                    }
                    None => {
                        // No packet received, continue checking
                        sleep(Duration::from_millis(10)).await;
                    }
                }
            }

            // No ACK received during this interval, retransmit
            if delay < RETRANSMIT_INTERVALS_US.last().unwrap_or(&0) {
                info!("Retransmitting packet after {}μs delay", delay);
                self.send_packet(ptype, payload)?;
            }
        }

        info!("No ACK received after all retransmission attempts");
        Ok(false)
    }

    async fn start_session(&mut self) -> Result<(), MacTelnetError> {
        info!("Sending Start session packet...");

        // Use protocol-specified retransmission intervals
        if !self
            .retransmit_with_intervals(PacketType::Start, &[])
            .await?
        {
            return Err(MacTelnetError::Timeout(
                "No ACK received after all retransmission attempts".into(),
            ));
        }

        info!("ACK received, session initiated!");
        Ok(())
    }

    async fn authenticate(&mut self) -> Result<(), MacTelnetError> {
        self.auth_state = AuthState::NotAuthenticated;
        let mut retry_count = 0;

        while retry_count < AUTH_RETRY_ATTEMPTS {
            if retry_count > 0 {
                info!(
                    "Retrying authentication (attempt {}/{})",
                    retry_count + 1,
                    AUTH_RETRY_ATTEMPTS
                );
                sleep(Duration::from_millis(AUTH_RETRY_DELAY_MS)).await;
            }

            // Send BeginAuth packet
            let begin_auth = self.authenticator.generate_begin_auth();
            info!("Sending BeginAuth packet...");
            self.send_packet(PacketType::Data, &begin_auth.to_bytes())?;
            self.auth_state = AuthState::BeginAuthSent;

            // Wait for encryptionKey from server
            let auth_start_time = Instant::now();
            let mut received_encryption_key = false;
            let mut end_auth_count = 0;

            while auth_start_time.elapsed() < Duration::from_secs(10) && !received_encryption_key {
                // Check for incoming packets
                match self.receive_packet()? {
                    Some((header, payload)) if header.ptype == PacketType::Data => {
                        // Send ACK for received data
                        self.send_packet(PacketType::Ack, &[])?;

                        if let Some(control) = self.extract_control_packet(&payload) {
                            match control.ctype {
                                ControlPacketType::EncryptionKey => {
                                    info!(
                                        "Received EncryptionKey packet with size: {} bytes",
                                        control.payload.len()
                                    );
                                    received_encryption_key = true;

                                    if control.payload.len() >= 16 {
                                        self.authenticator.set_password(self.password.clone());

                                        // Process encryption key and build combined response containing:
                                        // Password + Username + TerminalType + TerminalWidth + TerminalHeight
                                        match self
                                            .authenticator
                                            .process_encryption_key_complete(&control)
                                        {
                                            Ok(combined_response) => {
                                                info!("Sending complete authentication response package... ({} bytes)", combined_response.len());
                                                self.send_packet(
                                                    PacketType::Data,
                                                    &combined_response,
                                                )?;
                                                self.auth_state =
                                                    AuthState::WaitingForAuthConfirmation;

                                                // No need to send terminal size separately, it's included in the response
                                            }
                                            Err(e) => {
                                                warn!("Failed to process encryption key: {}", e);
                                                break;
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "Received malformed EncryptionKey packet (too short)"
                                        );
                                    }
                                }
                                ControlPacketType::EndAuth => {
                                    end_auth_count += 1;
                                    info!("Received EndAuth packet ({}/2)", end_auth_count);

                                    if end_auth_count >= 2 {
                                        info!("Authentication successful!");
                                        self.auth_state = AuthState::Authenticated;
                                        return Ok(());
                                    }
                                }
                                _ => {
                                    debug!(
                                        "Received control packet of type {:?}, payload size: {}",
                                        control.ctype,
                                        control.payload.len()
                                    );
                                }
                            }
                        } else if !payload.is_empty() {
                            // Non-control packet data may contain error messages
                            if let Ok(text) = std::str::from_utf8(&payload) {
                                if text.contains("Login failed") || text.contains("incorrect") {
                                    return Err(MacTelnetError::Authentication(format!(
                                        "Authentication failed: {}",
                                        text
                                    )));
                                }
                                debug!("Received text during auth: {}", text);
                            }
                        }
                    }
                    Some((header, _)) => {
                        // Handle ACKs and other packet types
                        debug!(
                            "Received packet of type {:?} during authentication",
                            header.ptype
                        );
                    }
                    None => {
                        // No packet received, wait a bit
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }

            // If we didn't receive an encryption key or authentication failed
            if !received_encryption_key {
                warn!("Did not receive encryption key from router");
            } else if self.auth_state != AuthState::Authenticated {
                if !self.wait_for_auth_confirmation().await? {
                    warn!("Authentication confirmation not received");
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            }

            retry_count += 1;
        }

        Err(MacTelnetError::Authentication(
            "Authentication failed after max retries".into(),
        ))
    }

    async fn wait_for_auth_confirmation(&mut self) -> Result<bool, MacTelnetError> {
        let start_time = Instant::now();
        let mut end_auth_count = 0;

        while start_time.elapsed() < Duration::from_secs(20)
            && self.auth_state != AuthState::Authenticated
        {
            match self.receive_packet()? {
                Some((header, payload)) if header.ptype == PacketType::Data => {
                    // Always ACK data packets
                    self.send_packet(PacketType::Ack, &[])?;

                    if let Some(control) = self.extract_control_packet(&payload) {
                        match control.ctype {
                            ControlPacketType::EndAuth => {
                                end_auth_count += 1;
                                info!("Received EndAuth packet ({}/2)", end_auth_count);

                                if end_auth_count >= 2 {
                                    info!("Authentication successful!");
                                    self.auth_state = AuthState::Authenticated;
                                    return Ok(true);
                                }
                            }
                            _ => {
                                debug!(
                                    "Received control packet type={:?} during auth confirmation",
                                    control.ctype
                                );
                            }
                        }
                    } else if !payload.is_empty() {
                        // Check for error messages in the payload
                        if let Ok(text) = std::str::from_utf8(&payload) {
                            if text.contains("Login failed") || text.contains("incorrect") {
                                return Err(MacTelnetError::Authentication(format!(
                                    "Authentication failed: {}",
                                    text
                                )));
                            }
                            debug!("Received text during auth confirmation: {}", text);
                        }
                    }
                }
                _ => {
                    // Wait a bit before checking again
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }

        Ok(self.auth_state == AuthState::Authenticated)
    }

    async fn terminal_loop(&mut self) -> Result<(), MacTelnetError> {
        let mut last_keepalive = Instant::now();
        let mut last_terminal_resize = Instant::now();

        self.send_terminal_size()?;

        info!("Session established, starting terminal mode");

        loop {
            // Handle incoming packets
            match self.receive_packet() {
                Ok(Some((header, payload))) => {
                    if !self.is_packet_for_me(&header) {
                        continue;
                    }

                    match header.ptype {
                        PacketType::Data => {
                            if !payload.is_empty() && payload[0..4] != CONTROL_PACKET_MAGIC {
                                std::io::stdout().write_all(&payload)?;
                                std::io::stdout().flush()?;
                            }
                        }
                        PacketType::Ack => {}
                        PacketType::End => {
                            info!("Received End packet, terminating session");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Error receiving: {}", e);
                    if e.is_network_error() {
                        return Err(e);
                    }
                }
            }

            // Check for terminal resize every second
            if last_terminal_resize.elapsed().as_secs() >= 1 {
                if terminal::size().is_ok() {
                    self.send_terminal_size()?;
                }
                last_terminal_resize = Instant::now();
            }

            // More frequent keepalives for better connection stability
            if last_keepalive.elapsed().as_secs() >= KEEPALIVE_INTERVAL_SEC / 2 {
                self.send_packet(PacketType::Ack, &[])?;
                last_keepalive = Instant::now();
            }

            // Handle user input
            if event::poll(Duration::from_millis(10))? {
                match event::read()? {
                    Event::Key(KeyEvent {
                        code: KeyCode::Char('c'),
                        modifiers,
                        ..
                    }) if modifiers.contains(KeyModifiers::CONTROL) => {
                        info!("Ctrl+C detected, terminating session");
                        break;
                    }
                    Event::Key(KeyEvent { code, .. }) => {
                        let key_data = match code {
                            KeyCode::Char(c) => vec![c as u8],
                            KeyCode::Enter => vec![13],
                            KeyCode::Backspace => vec![8],
                            KeyCode::Esc => vec![27],
                            KeyCode::Up => vec![27, 91, 65],
                            KeyCode::Down => vec![27, 91, 66],
                            KeyCode::Right => vec![27, 91, 67],
                            KeyCode::Left => vec![27, 91, 68],
                            _ => continue,
                        };

                        self.send_packet(PacketType::Data, &key_data)?;
                    }
                    _ => {}
                }
            }

            sleep(Duration::from_millis(5)).await;
        }

        Ok(())
    }

    fn send_terminal_size(&mut self) -> Result<(), MacTelnetError> {
        let terminal_size =
            terminal::size().map_err(|e| MacTelnetError::Terminal(e.to_string()))?;

        let width_packet = ControlPacket::new(
            ControlPacketType::Width,
            terminal_size.0.to_be_bytes().to_vec(),
        );

        let height_packet = ControlPacket::new(
            ControlPacketType::Height,
            terminal_size.1.to_be_bytes().to_vec(),
        );

        self.send_packet(PacketType::Data, &width_packet.to_bytes())?;
        self.send_packet(PacketType::Data, &height_packet.to_bytes())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pnet::{
        datalink::{self, DataLinkReceiver, DataLinkSender},
        ipnetwork::IpNetwork,
        util::MacAddr,
    };

    use super::*;

    fn create_mock_interface() -> NetworkInterface {
        NetworkInterface {
            name: String::from("mock0"),
            description: String::from("Mock interface for testing"),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 24).unwrap()],
            flags: 0,
        }
    }

    // Mock DataLinkSender for testing
    struct MockDataLinkSender;

    impl DataLinkSender for MockDataLinkSender {
        fn build_and_send(
            &mut self,
            len: usize,
            _packet_size: usize,
            func: &mut dyn FnMut(&mut [u8]),
        ) -> Option<io::Result<()>> {
            let mut buffer = vec![0u8; len];
            func(&mut buffer);
            Some(Ok(()))
        }

        fn send_to(
            &mut self,
            packet: &[u8],
            _dst: Option<NetworkInterface>,
        ) -> Option<io::Result<()>> {
            Some(Ok(()))
        }
    }

    // Mock DataLinkReceiver for testing
    struct MockDataLinkReceiver;

    impl DataLinkReceiver for MockDataLinkReceiver {
        fn next(&mut self) -> io::Result<&[u8]> {
            // Return a predefined packet for testing
            static PACKET: [u8; 30] = [
                0x01, 0x01, // ver, ptype
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // srcaddr
                0x00, 0x11, 0x22, 0x33, 0x44, 0x66, // dstaddr
                0x00, 0x15, 0x00, 0x00, // seskey
                0x00, 0x00, 0x00, 0x01, // counter
                0x68, 0x65, 0x6c, 0x6c, 0x6f, // "hello" payload
                0x00, 0x00, 0x00,
            ];
            Ok(&PACKET[..])
        }
    }

    #[test]
    fn test_session_creation() {
        let interface = create_mock_interface();
        let dst_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
        let username = String::from("testuser");
        let session = Session::new(interface, dst_mac, username).unwrap();
        assert_eq!(session.counter, 0);
    }

    #[test]
    fn test_packet_counter() {
        let interface = create_mock_interface();
        let dst_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
        let username = String::from("testuser");
        let mut session = Session::new(interface, dst_mac, username).unwrap();

        // Instead of calling connect(), mock the channel directly
        session.channel = Some(network::NetworkChannel {
            interface: create_mock_interface(),
            tx: Box::new(MockDataLinkSender {}),
            rx: Box::new(MockDataLinkReceiver {}),
        });

        assert_eq!(session.counter, 0);
        session.send_packet(PacketType::Data, &[]).unwrap();
        assert_eq!(session.counter, 1);
    }

    #[test]
    fn test_counter_wraparound() {
        let interface = create_mock_interface();
        let dst_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
        let username = String::from("testuser");
        let mut session = Session::new(interface, dst_mac, username).unwrap();

        // Instead of calling connect(), mock the channel directly
        session.channel = Some(network::NetworkChannel {
            interface: create_mock_interface(),
            tx: Box::new(MockDataLinkSender {}),
            rx: Box::new(MockDataLinkReceiver {}),
        });

        session.counter = u32::MAX;
        session.send_packet(PacketType::Data, &[]).unwrap();
        assert_eq!(session.counter, 0);
    }
}
