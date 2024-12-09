use std::time::{SystemTime, Instant};
use libsodium_sys::*;
use lhtlp::LHTLP;
use num_bigint::BigUint;
const TIME_HARDNESS: u64 = 340000; // Constant to take 1 second
const LAMBDA: u64 = 256;

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
        salt: [u8; crypto_pwhash_SALTBYTES as usize],
        hash: String,
        cpriv1: Vec<u8>,
        nonce1: [u8; crypto_secretbox_NONCEBYTES as usize],
        pub1: [u8; crypto_box_PUBLICKEYBYTES as usize],
        cpriv2: Vec<u8>,
        nonce2: [u8; crypto_secretbox_NONCEBYTES as usize],
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

    pub fn get_salt(& self, username: &str) -> Option<[u8; crypto_pwhash_SALTBYTES as usize]> {
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
    ) -> Result<([u8; crypto_box_PUBLICKEYBYTES as usize], Vec<u8>, [u8; crypto_secretbox_NONCEBYTES as usize], [u8; crypto_sign_PUBLICKEYBYTES as usize], Vec<u8>, [u8; crypto_secretbox_NONCEBYTES as usize]), Box<dyn std::error::Error>> {
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
        new_salt: [u8; crypto_pwhash_SALTBYTES as usize],
        new_hash: String,
        cpriv1: Vec<u8>,
        nonce1: [u8; crypto_secretbox_NONCEBYTES as usize],
        pub1: [u8; crypto_box_PUBLICKEYBYTES as usize],
        cpriv2: Vec<u8>,
        nonce2: [u8; crypto_secretbox_NONCEBYTES as usize],
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

            if m.delivery_time > now {

                // Generate time puzzles

                // time in seconds
                let time = m.delivery_time.duration_since(now).unwrap().as_secs();

                let complexity = time * TIME_HARDNESS / 3;

                let lhtlp = LHTLP::setup(LAMBDA, BigUint::from(complexity));

                let secret = u64::from_le_bytes(m.nonce_message[..8].try_into().unwrap()); // Premier bloc
                let secret2 = u64::from_le_bytes(m.nonce_message[8..16].try_into().unwrap()); // Deuxième bloc
                let secret3 = u64::from_le_bytes(m.nonce_message[16..].try_into().unwrap()); // Troisième bloc

                // Générer des puzzles pour chaque bloc
                let puzzle1 = lhtlp.generate(secret);
                let puzzle2 = lhtlp.generate(secret2);
                let puzzle3 = lhtlp.generate(secret3);


                // check the time needed
                // println!("Time needed to take in seconds: {:?}", time);
                //
                // let start_time = Instant::now();
                // let solution = lhtlp.solve(puzzle1.clone());
                // let solution = lhtlp.solve(puzzle1.clone());
                // let solution = lhtlp.solve(puzzle1.clone());
                // let duration = start_time.elapsed();
                //
                // println!("Time needed to solve the puzzle: {:?}", duration);

                m.puzzle_complexity = lhtlp;
                m.nonce_message = [0u8; crypto_box_NONCEBYTES as usize];
                m.puzzles = vec![puzzle1, puzzle2, puzzle3];
            }
        }

        Ok(copied_messages)
    }
}
