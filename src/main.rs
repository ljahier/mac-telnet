mod auth;
mod cli;
mod error;
mod network;
mod packet;
mod session;

use std::process;
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
        interface.mac.unwrap().to_string().clone()
    );
    // info!(
    //     "Connecting to router with MAC {}",
    //     args.mac.as_bytes().
    // );

    // Create a session
    let mut session = match session::Session::new(interface, *args.mac.as_bytes(), args.username) {
        Ok(session) => session,
        Err(e) => {
            error!("Session creation failed: {}", e);
            process::exit(3); // I/O Error
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
