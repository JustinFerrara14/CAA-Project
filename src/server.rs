use std::time::SystemTime;
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use ecies::PublicKey;
use libsodium_sys::*;
use generic_array::GenericArray;
use crate::database::{Database, Message};

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
        pub1: [u8; crypto_box_PUBLICKEYBYTES as usize],
        cpriv2: Vec<u8>,
        nonce2: GenericArray<u8, U12>,
        pub2: [u8; crypto_sign_PUBLICKEYBYTES as usize],
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

    pub fn get_pub_key1(& self, username: &str) -> Option<[u8; crypto_box_PUBLICKEYBYTES as usize]> {
        self.db.get_user(username).map(|u| u.asysm_key_encryption.public_key.clone())
    }

    pub fn get_pub_key2(& self, username: &str) -> Option<[u8; crypto_sign_PUBLICKEYBYTES as usize]> {
        self.db.get_user(username).map(|u| u.asysm_key_signing.public_key.clone())
    }

    /// Returns pub1, cpriv1, nonce1, pub2, cpriv2, nonce2
    pub fn login(
        & self,
        username: &str,
        hash: &str,
    ) -> Result<([u8; crypto_box_PUBLICKEYBYTES as usize], Vec<u8>, GenericArray<u8, U12>, [u8; crypto_sign_PUBLICKEYBYTES as usize], Vec<u8>, GenericArray<u8, U12>), Box<dyn std::error::Error>> {
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

    pub fn change_password(
        &mut self,
        username: String,
        hash: String,
        new_salt: String,
        new_hash: String,
        cpriv1: Vec<u8>,
        nonce1: GenericArray<u8, U12>,
        pub1: [u8; crypto_box_PUBLICKEYBYTES as usize],
        cpriv2: Vec<u8>,
        nonce2: GenericArray<u8, U12>,
        pub2: [u8; crypto_sign_PUBLICKEYBYTES as usize],
    ) -> Result<(), Box<dyn std::error::Error>> {

        if self.login(&username, &hash).is_err() {
            println!("User not connected");
            return Err("User not connected".into());
        }

        self.db.modify_user(
            username, new_salt, new_hash, cpriv1, nonce1, pub1, cpriv2, nonce2, pub2,
        )?;

        Ok(())
    }

    pub fn send_message(&mut self, hash: String, sender: &str, receiver: &str, delivery_time: SystemTime, filename: Vec<u8>, nonce_filename: [u8; crypto_box_NONCEBYTES as usize], message: Vec<u8>, nonce_message: [u8; crypto_box_NONCEBYTES as usize], signature: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {

        // Check if the user is connected using login function
        if self.login(sender, &hash).is_err() {
            println!("User not connected");
            return Err("User not connected".into());
        }

        self.db.send_message(sender, receiver, delivery_time, filename, nonce_filename, message, nonce_message, signature)?;

        Ok(())
    }

    pub fn get_messages(&mut self, hash: String, username: &str) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
        // Check if the user is connected
        if self.login(username, &hash).is_err() {
            println!("User not connected");
            return Err("User not connected".into());
        }

        let messages = self.db.get_messages(username)?;

        let now = SystemTime::now();

        // Make a copy of the messages
        let mut copied_messages: Vec<Message> = messages.iter().cloned().collect();

        // Remove the nonce_message if the delivery_time is in the future
        for m in &mut copied_messages {

            println!("Delivery time: {:?}", m.delivery_time);
            println!("Now: {:?}", now);

            if m.delivery_time > now {
                m.nonce_message = [0u8; crypto_box_NONCEBYTES as usize];
            }
        }

        Ok(copied_messages)
    }
}
