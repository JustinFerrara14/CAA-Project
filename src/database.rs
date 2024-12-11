use std::time::SystemTime;
use libsodium_sys::*;
use num_bigint::BigUint;
use lhtlp::LHTLP;
use opaque_ke::*;
use generic_array::GenericArray;
use generic_array::typenum::U64;

use crate::consts::*;
use crate::server::DefaultCipherSuite;

pub struct AsysmKeyEnc {
    pub(crate) public_key: [u8; ENC_KEY_LEN_PUB],
    pub(crate) nonce: [u8; SYM_LEN_NONCE],
    pub(crate) cipher_private_key: Vec<u8>,
}

pub struct AsysmKeySign {
    pub(crate) public_key: [u8; SIGN_KEY_LEN_PUB],
    pub(crate) nonce: [u8; SYM_LEN_NONCE],
    pub(crate) cipher_private_key: Vec<u8>,
}

#[derive(Clone)]
pub struct Message {
    pub(crate) sender: String,
    pub(crate) receiver: String,
    pub(crate) delivery_time: SystemTime,
    pub(crate) filename: Vec<u8>,
    pub(crate) nonce_filename: [u8; ENC_LEN_NONCE],
    pub(crate) message: Vec<u8>,
    pub(crate) nonce_message: [u8; ENC_LEN_NONCE],
    pub(crate) puzzle_struct: LHTLP,
    pub(crate) puzzles: Vec<(BigUint, BigUint)>,
    pub(crate) signature: Vec<u8>,
}
pub struct User {
    pub(crate) username: String,
    pub(crate) password_file: GenericArray<u8, ServerRegistrationLen<DefaultCipherSuite>>,
    pub(crate) asysm_key_encryption: AsysmKeyEnc,
    pub(crate) asysm_key_signing: AsysmKeySign,

    pub(crate) receive_messages: Vec<Message>,
}

pub struct ConnectedUser{
    pub(crate) username: String,
    pub(crate) key_communication: GenericArray<u8, U64>,
}

pub struct Database {
    users: Vec<User>,
    connected_user: ConnectedUser,
}

impl Database {
    pub fn new() -> Self {
        Database {
            users: Vec::new(),
            connected_user: ConnectedUser {
                username: String::new(),
                key_communication: GenericArray::default(),
            },
        }
    }

    pub fn connect_user(&mut self, username: String, key_communication: GenericArray<u8, U64>) -> Result<(), Box<dyn std::error::Error>> {
        self.connected_user = ConnectedUser {
            username,
            key_communication,
        };
        Ok(())
    }

    pub fn get_connected_user(&self) -> &ConnectedUser {
        &self.connected_user
    }

    pub fn create_user(
        &mut self,
        username: String,
        password_file: GenericArray<u8, ServerRegistrationLen<DefaultCipherSuite>>,
        cpriv1: Vec<u8>,
        nonce1: [u8; SYM_LEN_NONCE],
        pub1: [u8; ENC_KEY_LEN_PUB],
        cpriv2: Vec<u8>,
        nonce2: [u8; SYM_LEN_NONCE],
        pub2: [u8; SIGN_KEY_LEN_PUB],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.users.push(User {
            username,
            password_file,
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
        password_file: GenericArray<u8, ServerRegistrationLen<DefaultCipherSuite>>,
        cpriv1: Vec<u8>,
        nonce1: [u8; SYM_LEN_NONCE],
        pub1: [u8; ENC_KEY_LEN_PUB],
        cpriv2: Vec<u8>,
        nonce2: [u8; SYM_LEN_NONCE],
        pub2: [u8; SIGN_KEY_LEN_PUB],
    ) -> Result<(), Box<dyn std::error::Error>> {

        let user = self.get_user_mut(&username).ok_or("User not found")?;

        user.password_file = password_file;
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

    pub fn send_message(&mut self, sender: &str, receiver: &str, delivery_time: SystemTime, filename: Vec<u8>, nonce_filename: [u8; ENC_LEN_NONCE], message: Vec<u8>, nonce_message: [u8; ENC_LEN_NONCE], signature: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {

        let receiver = self.get_user_mut(receiver).ok_or("Recipient not found")?;

        receiver.receive_messages.push(Message {
            sender: sender.to_string(),
            receiver: receiver.username.clone(),
            delivery_time,
            filename,
            nonce_filename,
            message,
            nonce_message,
            puzzle_struct: LHTLP::setup(15, BigUint::try_from(15).unwrap()),
            puzzles: Vec::new(),
            signature,
        });

        Ok(())
    }

    pub fn get_messages(&self, username: &str) -> Result<&Vec<Message>, Box<dyn std::error::Error>> {
        let user = self.get_user(username).ok_or("User not found")?;
        Ok(&user.receive_messages)
    }
}
