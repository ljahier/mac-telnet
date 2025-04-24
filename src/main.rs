mod auth;
mod cli;
mod error;
mod network;
mod packet;
mod session;

use crate::packet::{Header, PacketType};
use std::process;
use std::time::Duration;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // Initialize logger
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    // Parse CLI arguments
    let args = match cli::parse_args() {
        Ok(args) => args,
        Err(e) => {
            error!("Argument error: {}", e);
            process::exit(1);
        }
    };

    // Find the specified network interface
    let interface = match network::find_interface(&args.interface) {
        Some(iface) => iface,
        None => {
            error!(
                "Network interface '{}' not found or has no MAC address",
                args.interface
            );
            process::exit(1);
        }
    };

    info!(
        "Using interface {} with MAC {}",
        interface.name,
        interface.mac.unwrap().to_string()
    );

    if args.list_routers {
        // Create network instance for discovery
        let network = match network::Network::new(interface.clone()) {
            Ok(net) => net,
            Err(e) => {
                error!("Failed to initialize network: {}", e);
                process::exit(1);
            }
        };

        // Send discovery packet
        let discovery_header = Header::new(
            interface.mac.unwrap().octets(),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // Broadcast MAC
            PacketType::Discovery,
            0,     // session key
            0,     // counter
            false, // is_server
        );

        if let Err(e) = network.send_packet(&discovery_header, &[]).await {
            error!("Failed to send discovery packet: {}", e);
            process::exit(1);
        }

        info!("Scanning for MikroTik routers...");

        // Wait and collect responses for 2 seconds
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(2);
        let mut found_routers = Vec::new();

        while start.elapsed() < timeout {
            if let Ok(Some((header, _))) = network.receive_packet(100).await {
                if header.ptype == PacketType::DiscoveryResponse {
                    let mac = header.srcaddr;
                    if !found_routers.contains(&mac) {
                        info!(
                            "Found router: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                        );
                        found_routers.push(mac);
                    }
                }
            }
        }

        if found_routers.is_empty() {
            info!("No MikroTik routers found on the network");
        }
        process::exit(0);
    }

    // If not listing routers, proceed with connection
    if args.mac.is_none() {
        error!("MAC address is required when not in list mode");
        process::exit(1);
    }

    info!("Connecting to router with MAC {:?}", args.mac);

    // Create a session
    let mut session = match session::Session::new(
        interface,
        *args.mac.as_ref().unwrap().as_bytes(),
        args.username,
    ) {
        Ok(session) => session,
        Err(e) => {
            error!("Session creation failed: {}", e);
            process::exit(3);
        }
    };

    // Run the session
    info!("Starting MAC-Telnet session...");
    match session.run().await {
        Ok(_) => {
            info!("Session terminated normally");
        }
        Err(e) => {
            error!("Session error: {}", e);
            let exit_code = match e {
                error::MacTelnetError::Authentication(_) => 1,
                error::MacTelnetError::Timeout(_) => 2,
                _ => 3,
            };
            process::exit(exit_code);
        }
    }
}
