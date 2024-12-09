use std::time::SystemTime;
use libsodium_sys::*;

pub struct AsysmKeyEnc {
    pub(crate) public_key: [u8; crypto_box_PUBLICKEYBYTES as usize],
    pub(crate) cipher_private_key: Vec<u8>,
    pub(crate) nonce: [u8; crypto_secretbox_NONCEBYTES as usize],
}

pub struct AsysmKeySign {
    pub(crate) public_key: [u8; crypto_sign_PUBLICKEYBYTES as usize],
    pub(crate) cipher_private_key: Vec<u8>,
    pub(crate) nonce: [u8; crypto_secretbox_NONCEBYTES as usize],
}

#[derive(Clone)]
pub struct Message {
    pub(crate) sender: String,
    pub(crate) receiver: String,
    pub(crate) delivery_time: SystemTime,
    pub(crate) filename: Vec<u8>,
    pub(crate) nonce_filename: [u8; crypto_box_NONCEBYTES as usize],
    pub(crate) message: Vec<u8>,
    pub(crate) nonce_message: [u8; crypto_box_NONCEBYTES as usize],
    pub(crate) signature: Vec<u8>,
}
pub struct User {
    pub(crate) username: String,
    pub(crate) salt: [u8; crypto_pwhash_SALTBYTES as usize],
    pub(crate) hash: String,
    pub(crate) asysm_key_encryption: AsysmKeyEnc,
    pub(crate) asysm_key_signing: AsysmKeySign,

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
        salt: [u8; crypto_pwhash_SALTBYTES as usize],
        hash: String,
        cpriv1: Vec<u8>,
        nonce1: [u8; crypto_secretbox_NONCEBYTES as usize],
        pub1: [u8; crypto_box_PUBLICKEYBYTES as usize],
        cpriv2: Vec<u8>,
        nonce2: [u8; crypto_secretbox_NONCEBYTES as usize],
        pub2: [u8; crypto_sign_PUBLICKEYBYTES as usize],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.users.push(User {
            username,
            salt,
            hash,
            asysm_key_encryption: AsysmKeyEnc {
                public_key: pub1,
                cipher_private_key: cpriv1,
                nonce: nonce1,
            },
            asysm_key_signing: AsysmKeySign {
                public_key: pub2,
                cipher_private_key: cpriv2,
                nonce: nonce2,
            },
            receive_messages: Vec::new(),
        });
        Ok(())
    }

    pub fn modify_user(
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

        let user = self.get_user_mut(&username).ok_or("User not found")?;

        user.salt = salt;
        user.hash = hash;
        user.asysm_key_encryption = AsysmKeyEnc {
            public_key: pub1,
            cipher_private_key: cpriv1,
            nonce: nonce1,
        };
        user.asysm_key_signing = AsysmKeySign {
            public_key: pub2,
            cipher_private_key: cpriv2,
            nonce: nonce2,
        };

        Ok(())
    }
    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }

    pub fn get_user_mut(&mut self, username: &str) -> Option<&mut User> {
        self.users.iter_mut().find(|u| u.username == username)
    }

    pub fn send_message(&mut self, sender: &str, receiver: &str, delivery_time: SystemTime, filename: Vec<u8>, nonce_filename: [u8; crypto_box_NONCEBYTES as usize], message: Vec<u8>, nonce_message: [u8; crypto_box_NONCEBYTES as usize], signature: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {

        let receiver = self.get_user_mut(receiver).ok_or("Recipient not found")?;

        receiver.receive_messages.push(Message {
            sender: sender.to_string(),
            receiver: receiver.username.clone(),
            delivery_time,
            filename,
            nonce_filename,
            message,
            nonce_message,
            signature,
        });

        Ok(())
    }

    pub fn get_messages(&self, username: &str) -> Result<&Vec<Message>, Box<dyn std::error::Error>> {
        let user = self.get_user(username).ok_or("User not found")?;
        Ok(&user.receive_messages)
    }
}
