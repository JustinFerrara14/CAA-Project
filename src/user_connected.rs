use generic_array::GenericArray;
use generic_array::typenum::U64;

use crate::consts::*;

pub struct UserConnected {
    username: String,
    key: Vec<u8>,
    key_communication: GenericArray<u8, U64>,
    mac: [u8; MAC_LEN],
    pub1: [u8; ENC_KEY_LEN_PUB],
    priv1: [u8; ENC_KEY_LEN_PRIV],
    pub2: [u8; SIGN_KEY_LEN_PUB],
    priv2: [u8; SIGN_KEY_LEN_PRIV],
}

impl UserConnected {
    pub fn new(
        username: String,
        key: Vec<u8>,
        key_communication: GenericArray<u8, U64>,
        mac: [u8; MAC_LEN],
        pub1: [u8; ENC_KEY_LEN_PUB],
        priv1: [u8; ENC_KEY_LEN_PRIV],
        pub2: [u8; SIGN_KEY_LEN_PUB],
        priv2: [u8; SIGN_KEY_LEN_PRIV],
    ) -> Self {
        UserConnected {
            username,
            key,
            key_communication,
            mac,
            pub1,
            priv1,
            pub2,
            priv2,
        }
    }

    pub fn get_username(&self) -> &str {
        &self.username
    }

    pub fn get_mac(&self) -> &[u8; MAC_LEN] {
        &self.mac
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