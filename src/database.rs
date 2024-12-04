

struct asysm_key {
    public_key: String,
    cipher_private_key: String,
}

struct user {
    username: String,
    sel: String,
    hash: String,
    asysm_key_encryption: asysm_key,
    asysm_key_signing: asysm_key,

    receive_messages: Vec<message>,
}

struct message { // ????
    sender: String,
    receiver: String,
    message: String,
    signature: String,
}

struct database {
    users: Vec<user>,
}