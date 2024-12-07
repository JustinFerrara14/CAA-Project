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
struct Message {
    // ????
    sender: String,
    receiver: String,
    message: String,
    signature: String, // ????
}
pub struct User {
    username: String,
    pub(crate) salt: String,
    pub(crate) hash: String,
    pub(crate) asysm_key_encryption: AsysmKey,
    pub(crate) asysm_key_signing: AsysmKey,

    receive_messages: Vec<Message>,
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
}
