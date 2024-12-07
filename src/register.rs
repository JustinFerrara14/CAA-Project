
use inquire::Text;
use crate::server::Server;

use ecies::{decrypt, encrypt, utils::generate_keypair, SecretKey, PublicKey};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

use generic_array::GenericArray;

/// return connected: bool, username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn register(srv: &mut Server) -> Result<(bool, String, String, Vec<u8>, PublicKey, SecretKey, PublicKey, SecretKey), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let password_confirm = Text::new("Confirm your password:").prompt()?;

    // useless key to return
    let (priv_key, pub_key) = generate_keypair();

    if password != password_confirm {
        println!("Passwords do not match");
        // return error
        return Err("Passwords do not match".into());
    }

    let salt = SaltString::generate(&mut OsRng).to_string();

    const HASH_LEN: usize = 96;
    let argon2 = Argon2::default();
    let mut output_key_material = [0u8; HASH_LEN];
    Argon2::default().hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output_key_material).expect("TODO: panic message");

    let password_hash = hex::encode(output_key_material);

    // take first 64 bytes as hash
    let hash = password_hash.chars().take(64).collect::<String>();
    let key_hex = password_hash.chars().skip(64).take(64).collect::<String>(); // 64 caractères hex pour 32 octets
    let key = hex::decode(key_hex)?;
    //let key = hex::decode(password_hash.chars().skip(64).collect::<String>())?;
    let key_array: [u8; 32] = key[..32].try_into().expect("slice with incorrect length");


    println!("Len password hash {}", password_hash.len() / 2);
    println!("Hash: {}", hash);
    println!("Len hash {}", hash.len());
    println!("Key: {:?}", key);
    println!("Len key {}", key.len());

    let (priv1, pub1) = generate_keypair();
    let (priv2, pub2) = generate_keypair(); // TODO change to edDSA

    println!("Private key 1: {:?}", priv1);
    println!("Private key 2: {:?}", priv2);

    let cipher = Aes256Gcm::new(&key_array.into());
    let nonce1 = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce2 = Aes256Gcm::generate_nonce(&mut OsRng);

    let cpriv1 = cipher.encrypt(&nonce1, priv1.serialize().as_ref()).expect("encryption failure!");
    let cpriv2 = cipher.encrypt(&nonce2, priv2.serialize().as_ref()).expect("encryption failure!");

    srv.register(username, salt, hash, (cpriv1), (nonce1), (pub1), (cpriv2), (nonce2), (pub2))?;


    Ok((false, "".to_string(), "".to_string(), vec![], pub_key, priv_key, pub_key, priv_key))
}