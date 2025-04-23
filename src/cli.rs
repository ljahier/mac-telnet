use crate::error::MacTelnetError;
use clap::{Error, Parser};
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(name = "mac-telnet")]
#[command(about = "MAC-Telnet client for MikroTik routers")]
pub struct Args {
    /// Network interface to use
    #[arg(short, long)]
    pub interface: String,

    /// Target router MAC address (format xx:xx:xx:xx:xx:xx)
    #[arg(short, long)]
    pub mac: MacAddress,

    /// Username for authentication
    #[arg(short, long, default_value = "admin")]
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct MacAddress([u8; 6]);

impl FromStr for MacAddress {
    type Err = MacTelnetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 6 {
            return Err(MacTelnetError::InvalidMac(
                "MAC address must contain 6 bytes separated by ':'".to_string(),
            ));
        }

        let mut bytes = [0u8; 6];

        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).map_err(|_| {
                MacTelnetError::InvalidMac(format!("Non-hexadecimal value: {}", part))
            })?;
        }

        Ok(MacAddress(bytes))
    }
}

impl MacAddress {
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

pub fn parse_args() -> Result<Args, Error> {
    Ok(Args::parse())
}
