use libsodium_sys::*;

use crate::consts::*;

pub struct UserConnected {
    connected: bool,
    username: String,
    h: String,
    k: Vec<u8>,
    pub1: [u8; ENC_KEY_LEN_PUB],
    priv1: [u8; ENC_KEY_LEN_PRIV],
    pub2: [u8; SIGN_KEY_LEN_PUB],
    priv2: [u8; SIGN_KEY_LEN_PRIV],
}

impl UserConnected {
    pub fn new(
        connected: bool,
        username: String,
        h: String,
        k: Vec<u8>,
        pub1: [u8; ENC_KEY_LEN_PUB],
        priv1: [u8; ENC_KEY_LEN_PRIV],
        pub2: [u8; SIGN_KEY_LEN_PUB],
        priv2: [u8; SIGN_KEY_LEN_PRIV],
    ) -> Self {
        UserConnected {
            connected,
            username,
            h,
            k,
            pub1,
            priv1,
            pub2,
            priv2,
        }
    }

    pub fn get_username(&self) -> &str {
        &self.username
    }

    pub fn get_h(&self) -> &str {
        &self.h
    }

    pub fn get_k(&self) -> &Vec<u8> {
        &self.k
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