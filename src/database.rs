use std::time::SystemTime;
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use aes_gcm::{aead, AesGcm, Nonce};
use ecies::PublicKey;
use generic_array::GenericArray;

pub struct AsysmKey {
    pub(crate) public_key: PublicKey,
    pub(crate) cipher_private_key: Vec<u8>,
    pub(crate) nonce: GenericArray<u8, U12>,
}
pub struct Message {
    pub(crate) sender: String,
    pub(crate) receiver: String,
    pub(crate) delivery_time: SystemTime,
    pub(crate) filename: Vec<u8>,
    pub(crate) message: Vec<u8>,
    pub(crate) signature: String, // ????
}
pub struct User {
    pub(crate) username: String,
    pub(crate) salt: String,
    pub(crate) hash: String,
    pub(crate) asysm_key_encryption: AsysmKey,
    pub(crate) asysm_key_signing: AsysmKey,

    pub(crate) receive_messages: Vec<Message>,
}

pub struct Database {
    users: Vec<User>,
}

impl Database {
    pub fn new() -> Self {
        Database { users: Vec::new() }
    }

    pub fn create_user(
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
        self.users.push(User {
            username,
            salt,
            hash,
            asysm_key_encryption: AsysmKey {
                public_key: pub1,
                cipher_private_key: cpriv1,
                nonce: nonce1,
            },
            asysm_key_signing: AsysmKey {
                public_key: pub2,
                cipher_private_key: cpriv2,
                nonce: nonce2,
            },
            receive_messages: Vec::new(),
        });
        Ok(())
    }

    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }

    pub fn get_user_mut(&mut self, username: &str) -> Option<&mut User> {
        self.users.iter_mut().find(|u| u.username == username)
    }

    pub fn send_message(&mut self, sender: &str, receiver: &str, filename: Vec<u8>, delivery_time: SystemTime, message: Vec<u8>, signature: String) -> Result<(), Box<dyn std::error::Error>> {

        let receiver = self.get_user_mut(receiver).ok_or("Recipient not found")?;

        receiver.receive_messages.push(Message {
            sender: sender.to_string(),
            receiver: receiver.username.clone(),
            delivery_time,
            filename,
            message,
            signature,
        });

        Ok(())
    }

    pub fn get_messages(&self, username: &str) -> Result<&Vec<Message>, Box<dyn std::error::Error>> {
        let user = self.get_user(username).ok_or("User not found")?;
        Ok(&user.receive_messages)
    }
}
