use generic_array::GenericArray;
use generic_array::typenum::U64;

use crate::consts::*;

pub struct UserConnected {
    connected: bool,
    username: String,
    key: Vec<u8>,
    key_communication: GenericArray<u8, U64>,
    pub1: [u8; ENC_KEY_LEN_PUB],
    priv1: [u8; ENC_KEY_LEN_PRIV],
    pub2: [u8; SIGN_KEY_LEN_PUB],
    priv2: [u8; SIGN_KEY_LEN_PRIV],
}

impl UserConnected {
    pub fn new(
        connected: bool,
        username: String,
        key: Vec<u8>,
        key_communication: GenericArray<u8, U64>,
        pub1: [u8; ENC_KEY_LEN_PUB],
        priv1: [u8; ENC_KEY_LEN_PRIV],
        pub2: [u8; SIGN_KEY_LEN_PUB],
        priv2: [u8; SIGN_KEY_LEN_PRIV],
    ) -> Self {
        UserConnected {
            connected,
            username,
            key,
            key_communication,
            pub1,
            priv1,
            pub2,
            priv2,
        }
    }

    pub fn get_username(&self) -> &str {
        &self.username
    }

    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn get_key_communication(&self) -> &GenericArray<u8, U64> {
        &self.key_communication
    }

    pub fn get_pub_enc(&self) -> &[u8; ENC_KEY_LEN_PUB] {
        &self.pub1
    }

    pub fn get_priv_enc(&self) -> &[u8; ENC_KEY_LEN_PRIV] {
        &self.priv1
    }

    pub fn get_pub_sign(&self) -> &[u8; SIGN_KEY_LEN_PUB] {
        &self.pub2
    }

    pub fn get_priv_sign(&self) -> &[u8; SIGN_KEY_LEN_PRIV] {
        &self.priv2
    }
}