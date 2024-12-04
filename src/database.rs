struct AsysmKey {
    public_key: String,
    cipher_private_key: String,
}
struct Message {
    // ????
    sender: String,
    receiver: String,
    message: String,
    signature: String,
}
struct User {
    username: String,
    salt: String,
    hash: String,
    asysm_key_encryption: AsysmKey,
    asysm_key_signing: AsysmKey,

    receive_messages: Vec<Message>,
}

pub struct Database {
    users: Vec<User>,
}

impl Database {
    pub fn new() -> Self {
        Database { users: Vec::new() }
    }

    pub fn register(
        &mut self,
        username: String,
        salt: String,
        hash: String,
        cpriv1: String,
        pub1: String,
        cpriv2: String,
        pub2: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.users.push(User {
            username,
            salt,
            hash,
            asysm_key_encryption: AsysmKey {
                public_key: pub1,
                cipher_private_key: cpriv1,
            },
            asysm_key_signing: AsysmKey {
                public_key: pub2,
                cipher_private_key: cpriv2,
            },
            receive_messages: Vec::new(),
        });
        Ok(())
    }

}
