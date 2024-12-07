use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use ecies::PublicKey;
use generic_array::GenericArray;
use crate::database::Database;

pub struct Server {
    pub(crate) db: Database,
}

impl Server {
    pub fn new() -> Self {
        Server {
            db: Database::new(),
        }
    }

    pub fn register(
        &mut self,
        username: String,
        salt: String,
        hash: String,
        cpriv1: Vec<u8>,
        nonce1: GenericArray<u8, U12>,
        pub1: PublicKey,
        cpriv2: Vec<u8>,
        nonce2: GenericArray<u8, U12>,
        pub2: PublicKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.db.get_user(&username).is_some() {
            println!("User already exists");
            return Err("User already exists".into());
        }

        self.db.create_user(
            username, salt, hash, cpriv1, nonce1, pub1, cpriv2, nonce2, pub2,
        )?;
        Ok(())
    }

    pub fn get_salt(&self, username: &str) -> Option<String> {
        self.db.get_user(username).map(|u| u.salt.clone())
    }

    /// Returns pub1, cpriv1, nonce1, pub2, cpriv2, nonce2
    pub fn login(
        &self,
        username: &str,
        hash: &str,
    ) -> Result<(PublicKey, Vec<u8>, GenericArray<u8, U12>, PublicKey, Vec<u8>, GenericArray<u8, U12>), Box<dyn std::error::Error>> {
        let user = self.db.get_user(username).ok_or("User not found")?;
        if user.hash != hash {
            println!("Invalid password");
            return Err("Invalid password".into());
        }

        Ok((
            user.asysm_key_encryption.public_key.clone(),
            user.asysm_key_encryption.cipher_private_key.clone(),
            user.asysm_key_encryption.nonce.clone(),
            user.asysm_key_signing.public_key.clone(),
            user.asysm_key_signing.cipher_private_key.clone(),
            user.asysm_key_signing.nonce.clone(),
        ))
    }
}
