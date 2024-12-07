use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use ecies::PublicKey;
use generic_array::GenericArray;
use crate::database::{Database};

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

    pub fn get_salt(& self, username: &str) -> Option<String> {
        self.db.get_user(username).map(|u| u.salt.clone())
    }

    pub fn get_pub_key(& self, username: &str) -> Option<PublicKey> {
        self.db.get_user(username).map(|u| u.asysm_key_encryption.public_key.clone())
    }

    /// Returns pub1, cpriv1, nonce1, pub2, cpriv2, nonce2
    pub fn login(
        & self,
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

    pub fn send_message(&mut self, hash: String, sender: &str, receiver: &str, filename: Vec<u8>, message: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {

        // Check if the user is connected using login function
        if self.login(sender, &hash).is_err() {
            println!("User not connected");
            return Err("User not connected".into());
        }

        self.db.send_message(sender, receiver, filename, message)?;

        Ok(())
    }

    pub fn get_messages(&mut self, hash: String, username: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error>> {
        // Check if the user is connected
        if self.login(username, &hash).is_err() {
            println!("User not connected");
            return Err("User not connected".into());
        }

        let messages = self.db.get_messages(username)?;

        // Return filename and message as tuples of (Vec<u8>, Vec<u8>)
        let vec: Vec<(Vec<u8>, Vec<u8>)> = messages.iter()
            .map(|m| (m.filename.clone(), m.message.clone()))
            .collect();

        Ok(vec)
    }
}
