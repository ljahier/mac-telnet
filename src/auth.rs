use crate::error::MacTelnetError;
use crate::packet::control::{ControlPacket, ControlPacketType};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use srp::groups::G_2048;
use tracing::info;

pub struct Authenticator {
    username: String,
    password: Option<String>,
    salt: Option<[u8; 16]>,
    server_public_key: Option<Vec<u8>>,
    shared_key: Option<Vec<u8>>,
}

impl Authenticator {
    pub fn new(username: String) -> Self {
        Authenticator {
            username,
            password: None,
            salt: None,
            server_public_key: None,
            shared_key: None,
        }
    }

    pub fn set_password(&mut self, password: String) {
        self.password = Some(password);
    }

    pub fn generate_begin_auth(&self) -> ControlPacket {
        ControlPacket::new(ControlPacketType::BeginAuth, Vec::new())
    }

    pub fn generate_username(&self) -> ControlPacket {
        ControlPacket::new(
            ControlPacketType::Username,
            self.username.as_bytes().to_vec(),
        )
    }

    fn calculate_x(&self) -> Result<BigUint, MacTelnetError> {
        let password = self
            .password
            .as_ref()
            .ok_or_else(|| MacTelnetError::Authentication("Password not set".into()))?;
        let salt = self
            .salt
            .ok_or_else(|| MacTelnetError::Authentication("Salt not received".into()))?;

        // x = SHA1(salt | SHA1(username | ":" | password))
        let mut inner_hash = Sha256::new();
        inner_hash.update(self.username.as_bytes());
        inner_hash.update(b":");
        inner_hash.update(password.as_bytes());
        let inner = inner_hash.finalize();

        let mut outer_hash = Sha256::new();
        outer_hash.update(&salt);
        outer_hash.update(&inner);
        let result = outer_hash.finalize();

        Ok(BigUint::from_bytes_be(&result))
    }

    fn calculate_client_proof(
        &self,
        a_pub: &BigUint,
        b_pub: &[u8],
    ) -> Result<Vec<u8>, MacTelnetError> {
        let x = self.calculate_x()?;

        // Calculate u = SHA1(A | B)
        let mut u_hash = Sha256::new();
        u_hash.update(&a_pub.to_bytes_be());
        u_hash.update(b_pub);
        let u = BigUint::from_bytes_be(&u_hash.finalize());

        // Calculate k = SHA1(N | g)
        let k = compute_k();

        // Calculate client proof M1 = SHA1(A | B | K)
        let mut m1_hash = Sha256::new();
        m1_hash.update(&a_pub.to_bytes_be());
        m1_hash.update(b_pub);
        // Include private components in hash
        m1_hash.update(&k.to_bytes_be());
        m1_hash.update(&u.to_bytes_be());
        m1_hash.update(&x.to_bytes_be());

        Ok(m1_hash.finalize().to_vec())
    }

    pub fn process_encryption_key(
        &mut self,
        key_packet: &ControlPacket,
    ) -> Result<ControlPacket, MacTelnetError> {
        if key_packet.ctype != ControlPacketType::EncryptionKey {
            return Err(MacTelnetError::Protocol("Invalid key packet type".into()));
        }

        if key_packet.payload.len() < 16 {
            return Err(MacTelnetError::Protocol(
                "EncryptionKey packet too short".into(),
            ));
        }

        // Extract salt and server public key
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&key_packet.payload[0..16]);
        self.salt = Some(salt);

        let server_public_key = key_packet.payload[16..].to_vec();
        self.server_public_key = Some(server_public_key.clone());

        // Generate client's public key and proof
        let a = BigUint::from(1234u32); // For testing only, should be random
        let (g, n) = get_srp_params();
        let a_pub = g.modpow(&a, &n);

        let client_proof = self.calculate_client_proof(&a_pub, &server_public_key)?;

        // Build response
        let mut response = Vec::new();
        response.extend_from_slice(&a_pub.to_bytes_be());
        response.extend_from_slice(&client_proof);

        info!(
            "Authentication response generated: {} bytes",
            response.len()
        );

        Ok(ControlPacket::new(ControlPacketType::Password, response))
    }

    pub fn verify_server_proof(&self, proof: &[u8]) -> Result<bool, MacTelnetError> {
        // In a real implementation, verify M2 = SHA1(A | M1 | K)
        let expected_proof = self
            .shared_key
            .as_ref()
            .ok_or_else(|| MacTelnetError::Authentication("No shared key available".into()))?;

        Ok(expected_proof == proof)
    }
}

pub fn compute_k() -> BigUint {
    let mut k_hash = Hmac::<Sha256>::new_from_slice(&[]).unwrap();
    k_hash.update(&G_2048.n.to_bytes_be());
    k_hash.update(&G_2048.g.to_bytes_be());
    BigUint::from_bytes_be(&k_hash.finalize().into_bytes())
}

pub fn get_srp_params() -> (BigUint, BigUint) {
    let g = BigUint::from_bytes_be(&G_2048.g.to_bytes_be());
    let n = BigUint::from_bytes_be(&G_2048.n.to_bytes_be());
    (g, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_authenticator() -> Authenticator {
        let mut auth = Authenticator::new("admin".to_string());
        auth.set_password("password123".to_string());
        auth
    }

    #[test]
    fn test_begin_auth_packet() {
        let auth = create_test_authenticator();
        let packet = auth.generate_begin_auth();

        assert_eq!(packet.ctype, ControlPacketType::BeginAuth);
        assert!(packet.payload.is_empty());
    }

    #[test]
    fn test_username_packet() {
        let auth = create_test_authenticator();
        let packet = auth.generate_username();

        assert_eq!(packet.ctype, ControlPacketType::Username);
        assert_eq!(packet.payload, b"admin");
    }

    #[test]
    fn test_process_encryption_key() {
        let mut auth = create_test_authenticator();

        // Create a test encryption key packet
        let mut key_data = Vec::new();
        key_data.extend_from_slice(&[1u8; 16]); // Salt
        key_data.extend_from_slice(&[2u8; 32]); // Server public key

        let key_packet = ControlPacket::new(ControlPacketType::EncryptionKey, key_data);

        let response = auth.process_encryption_key(&key_packet).unwrap();

        assert_eq!(response.ctype, ControlPacketType::Password);
        assert!(!response.payload.is_empty());
    }

    #[test]
    fn test_invalid_encryption_key() {
        let mut auth = create_test_authenticator();

        // Test with invalid packet type
        let invalid_packet = ControlPacket::new(ControlPacketType::BeginAuth, Vec::new());
        assert!(auth.process_encryption_key(&invalid_packet).is_err());

        // Test with too short payload
        let short_packet = ControlPacket::new(ControlPacketType::EncryptionKey, vec![1; 15]);
        assert!(auth.process_encryption_key(&short_packet).is_err());
    }

    #[test]
    fn test_calculate_x() {
        let mut auth = create_test_authenticator();
        auth.salt = Some([1u8; 16]);

        let x = auth.calculate_x().unwrap();
        assert!(!x.to_bytes_be().is_empty());
    }

    #[test]
    fn test_calculate_x_no_password() {
        let auth = Authenticator::new("admin".to_string());
        assert!(auth.calculate_x().is_err());
    }

    #[test]
    fn test_calculate_x_no_salt() {
        let mut auth = Authenticator::new("admin".to_string());
        auth.set_password("password123".to_string());
        assert!(auth.calculate_x().is_err());
    }

    #[test]
    fn test_client_proof_calculation() {
        let mut auth = create_test_authenticator();
        auth.salt = Some([1u8; 16]);

        let a_pub = BigUint::from(12345u32);
        let b_pub = vec![2u8; 32];

        let proof = auth.calculate_client_proof(&a_pub, &b_pub).unwrap();
        assert_eq!(proof.len(), 32); // SHA-256 output size
    }
}
