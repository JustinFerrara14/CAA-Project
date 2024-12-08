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

use libsodium_sys::*;

use generic_array::GenericArray;
use crate::user_connected::UserConnected;

/// return connected: bool, username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn login(srv: &mut Server) -> Result<(bool, String, String, Vec<u8>, [u8; crypto_box_PUBLICKEYBYTES as usize], [u8; crypto_box_SECRETKEYBYTES as usize], [u8; crypto_sign_PUBLICKEYBYTES as usize], [u8; crypto_sign_SECRETKEYBYTES as usize]), Box<dyn std::error::Error>> {
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

    // put in Secret Key crypto_box_keypair
    let priv1 = priv1.try_into().expect("slice with incorrect length");

    // put in Secret Key ed25519
    let priv2 = priv2.try_into().expect("slice with incorrect length");

    println!("Private key 1: {:?}", priv1);
    println!("Private key 2: {:?}", priv2);

    Ok((true, username, hash, key, pub1, priv1, pub2, priv2))
}

pub fn change_password(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {

    let password = Text::new("Enter your new password:").prompt()?;
    let password_confirm = Text::new("Confirm your new password:").prompt()?;

    if password != password_confirm {
        println!("Passwords do not match");
        // return error
        return Err("Passwords do not match".into());
    }

    let new_salt = SaltString::generate(&mut OsRng).to_string();

    const HASH_LEN: usize = 96;
    let argon2 = Argon2::default();
    let mut output_key_material = [0u8; HASH_LEN];
    Argon2::default().hash_password_into(password.as_bytes(), new_salt.as_bytes(), &mut output_key_material).expect("TODO: panic message");

    let new_password_hash = hex::encode(output_key_material);

    let new_hash = new_password_hash.chars().take(64).collect::<String>();
    let new_key_hex = new_password_hash.chars().skip(64).take(64).collect::<String>(); // 64 caractères hex pour 32 octets
    let new_key = hex::decode(new_key_hex)?;
    //let key = hex::decode(password_hash.chars().skip(64).collect::<String>())?;
    let new_key_array: [u8; 32] = new_key[..32].try_into().expect("slice with incorrect length");

    println!("Password hash: {}", new_password_hash);
    println!("Len password hash {}", new_password_hash.len() / 2);
    println!("Hash: {}", new_hash);
    println!("Len hash {}", new_hash.len());
    println!("Key: {:?}", new_key);
    println!("Len key {}", new_key.len());

    let cipher = Aes256Gcm::new(&new_key_array.into());
    let nonce1 = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce2 = Aes256Gcm::generate_nonce(&mut OsRng);

    let cpriv1 = cipher.encrypt(&nonce1, &usr.get_priv1()[..]).expect("encryption failure!");
    let cpriv2 = cipher.encrypt(&nonce2, &usr.get_priv2()[..]).expect("encryption failure!");


    srv.change_password(usr.get_username().parse().unwrap(), usr.get_h().parse().unwrap(), new_salt, new_hash, cpriv1, nonce1, *usr.get_pub1(), cpriv2, nonce2, *usr.get_pub2())?;

    Ok(())
}