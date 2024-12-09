use libsodium_sys::*;

pub struct UserConnected {
    connected: bool,
    username: String,
    h: String,
    k: Vec<u8>,
    pub1: [u8; crypto_box_PUBLICKEYBYTES as usize],
    priv1: [u8; crypto_box_SECRETKEYBYTES as usize],
    pub2: [u8; crypto_sign_PUBLICKEYBYTES as usize],
    priv2: [u8; crypto_sign_SECRETKEYBYTES as usize],
}

impl UserConnected {
    pub fn new(
        connected: bool,
        username: String,
        h: String,
        k: Vec<u8>,
        pub1: [u8; crypto_box_PUBLICKEYBYTES as usize],
        priv1: [u8; crypto_box_SECRETKEYBYTES as usize],
        pub2: [u8; crypto_sign_PUBLICKEYBYTES as usize],
        priv2: [u8; crypto_sign_SECRETKEYBYTES as usize],
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

    pub fn get_pub1(&self) -> &[u8; crypto_box_PUBLICKEYBYTES as usize] {
        &self.pub1
    }

    pub fn get_priv1(&self) -> &[u8; crypto_box_SECRETKEYBYTES as usize] {
        &self.priv1
    }

    pub fn get_pub2(&self) -> &[u8; crypto_sign_PUBLICKEYBYTES as usize] {
        &self.pub2
    }

    pub fn get_priv2(&self) -> &[u8; crypto_sign_SECRETKEYBYTES as usize] {
        &self.priv2
    }
}