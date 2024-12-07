use ecies::{SecretKey, PublicKey};

pub struct UserConnected {
    connected: bool,
    username: String,
    h: String,
    k: Vec<u8>,
    pub1: PublicKey,
    priv1: SecretKey,
    pub2: PublicKey,
    priv2: SecretKey,
}

impl UserConnected {
    pub fn new(
        connected: bool,
        username: String,
        h: String,
        k: Vec<u8>,
        pub1: PublicKey,
        priv1: SecretKey,
        pub2: PublicKey,
        priv2: SecretKey,
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

    pub fn get_pub1(&self) -> &PublicKey {
        &self.pub1
    }

    pub fn get_priv1(&self) -> &SecretKey {
        &self.priv1
    }

    pub fn get_pub2(&self) -> &PublicKey {
        &self.pub2
    }

    pub fn get_priv2(&self) -> &SecretKey {
        &self.priv2
    }
}