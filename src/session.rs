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
const RETRANSMIT_INTERVALS_US: &[u64] = &[1000000, 1000000, 1000000]; // 1 second intervals
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
                    return Ok(None);
                }

                if let Some(header) = Header::from_bytes(&packet[0..22], true) {
                    let payload = packet[22..].to_vec();
                    return Ok(Some((header, payload)));
                }
                Ok(None)
            }
            Err(e) => Err(MacTelnetError::Network(e.to_string())),
        }
    }

    fn is_packet_for_me(&self, header: &Header) -> bool {
        if header.dstaddr != self.src_mac {
            return false;
        }

        if self.auth_state != AuthState::Authenticated {
            return header.srcaddr == self.dst_mac;
        }

        header.srcaddr == self.dst_mac && header.seskey == self.seskey
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
        for delay in RETRANSMIT_INTERVALS_US {
            if delay > &0 {
                sleep(Duration::from_micros(*delay)).await;
            }

            self.send_packet(ptype, payload)?;

            // Check for acknowledgment
            match self.receive_packet()? {
                Some((header, _)) if header.ptype == PacketType::Ack => {
                    return Ok(true);
                }
                _ => continue,
            }
        }

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

            let begin_auth = self.authenticator.generate_begin_auth();
            info!("Sending BeginAuth packet...");
            self.send_packet(PacketType::Data, &begin_auth.to_bytes())?;
            self.auth_state = AuthState::BeginAuthSent;

            let username_packet = self.authenticator.generate_username();
            info!("Sending username...");
            self.send_packet(PacketType::Data, &username_packet.to_bytes())?;
            self.auth_state = AuthState::UsernameSent;

            let mut end_auth_count = 0;
            let auth_start_time = Instant::now();

            while self.auth_state != AuthState::Authenticated
                && auth_start_time.elapsed() < Duration::from_secs(30)
            {
                match self.receive_packet()? {
                    Some((header, payload)) if header.ptype == PacketType::Data => {
                        if let Some(control) = self.extract_control_packet(&payload) {
                            match control.ctype {
                                ControlPacketType::EncryptionKey => {
                                    info!("Received EncryptionKey packet");

                                    if control.payload.len() >= 16 {
                                        self.authenticator.set_password(self.password.clone());

                                        match self.authenticator.process_encryption_key(&control) {
                                            Ok(response) => {
                                                info!("Sending authentication response...");
                                                self.send_packet(
                                                    PacketType::Data,
                                                    &response.to_bytes(),
                                                )?;
                                                self.auth_state =
                                                    AuthState::WaitingForAuthConfirmation;
                                            }
                                            Err(e) => {
                                                return Err(MacTelnetError::Authentication(
                                                    format!("Error in SRP calculation: {}", e),
                                                ));
                                            }
                                        }
                                    } else {
                                        warn!("Malformed EncryptionKey, insufficient size");
                                    }
                                }
                                ControlPacketType::EndAuth => {
                                    info!("Received EndAuth packet ({})", end_auth_count + 1);
                                    end_auth_count += 1;

                                    if end_auth_count >= 2 {
                                        info!("Authentication successful!");
                                        self.auth_state = AuthState::Authenticated;
                                        break;
                                    }
                                }
                                _ => {
                                    debug!(
                                        "Received control packet type={:?}, ignored",
                                        control.ctype
                                    );
                                }
                            }
                        }
                    }
                    _ => {
                        if self.auth_state == AuthState::BeginAuthSent {
                            let begin_auth = self.authenticator.generate_begin_auth();
                            self.send_packet(PacketType::Data, &begin_auth.to_bytes())?;
                        } else if self.auth_state == AuthState::UsernameSent {
                            let username_packet = self.authenticator.generate_username();
                            self.send_packet(PacketType::Data, &username_packet.to_bytes())?;
                        }
                    }
                }

                sleep(Duration::from_millis(100)).await;
            }

            if self.auth_state == AuthState::Authenticated {
                return Ok(());
            }

            retry_count += 1;
        }

        Err(MacTelnetError::Authentication(
            "Authentication failed after max retries".into(),
        ))
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

    use pnet::{ipnetwork::IpNetwork, util::MacAddr};

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

        // Create and set the channel
        session.connect().unwrap();

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

        // Create and set the channel
        session.connect().unwrap();

        session.counter = u32::MAX;
        session.send_packet(PacketType::Data, &[]).unwrap();
        assert_eq!(session.counter, 0);
    }
}
