use crate::server::Server;
use inquire::Text;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

use ecies::{decrypt, encrypt, utils::generate_keypair, SecretKey, PublicKey};

use generic_array::GenericArray;


/// return connected: bool, username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn login(srv: &mut Server) -> Result<(bool, String, String, Vec<u8>, PublicKey, SecretKey, PublicKey, SecretKey), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;

    let salt = srv.get_salt(&username).ok_or("User not found")?;

    const HASH_LEN: usize = 96;

    let argon2 = Argon2::default();

    let mut output_key_material = [0u8; HASH_LEN];
    Argon2::default().hash_password_into(password.as_bytes(), salt.as_bytes(), &mut output_key_material).expect("TODO: panic message");

    let password_hash = hex::encode(output_key_material);


    let hash = password_hash.chars().take(64).collect::<String>();
    let key_hex = password_hash.chars().skip(64).take(64).collect::<String>(); // 64 caractères hex pour 32 octets
    let key = hex::decode(key_hex)?;
    //let key = hex::decode(password_hash.chars().skip(64).collect::<String>())?;
    let key_array: [u8; 32] = key[..32].try_into().expect("slice with incorrect length");


    println!("Password hash: {}", password_hash);
    println!("Len password hash {}", password_hash.len() / 2);
    println!("Hash: {}", hash);
    println!("Len hash {}", hash.len());
    println!("Key: {:?}", key);
    println!("Len key {}", key.len());

    let (pub1, cpriv1, nonce1, pub2, cpriv2, nonce2) = srv.login(&username, &hash)?;


    let cipher = Aes256Gcm::new(&key_array.into());
    let priv1 = cipher.decrypt(&nonce1, cpriv1.as_ref()).expect("decryption failure!");
    let priv2 = cipher.decrypt(&nonce2, cpriv2.as_ref()).expect("encryption failure!");

    // put in Secret Key ecies
    let priv1 = SecretKey::parse_slice(&priv1).expect("parse failure!");
    let priv2 = SecretKey::parse_slice(&priv2).expect("parse failure!");

    println!("Private key 1: {:?}", priv1);
    println!("Private key 2: {:?}", priv2);

    Ok((true, username, hash, key, pub1, priv1, pub2, priv2))
}
