use libsodium_sys::*;
use inquire::Text;

use crate::server::Server;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use generic_array::GenericArray;

/// return connected: bool, username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn register(srv: &mut Server) -> Result<(bool, String, String, Vec<u8>, [u8; crypto_box_PUBLICKEYBYTES as usize], [u8; crypto_box_SECRETKEYBYTES as usize], [u8; crypto_sign_PUBLICKEYBYTES as usize], [u8; crypto_sign_SECRETKEYBYTES as usize]), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let password_confirm = Text::new("Confirm your password:").prompt()?;

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


    // Key for encryption
    let mut pub1 = [0u8; crypto_box_PUBLICKEYBYTES as usize];
    let mut priv1 = [0u8; crypto_box_SECRETKEYBYTES as usize];
    let result = unsafe { crypto_box_keypair(pub1.as_mut_ptr(), priv1.as_mut_ptr()) };

    if result != 0 {
        return Err("Failed to generate encryption keypair".into());
    }

    // Key for signing using ed25519 crypto_sign_ed25519_keypair
    let mut pub2 = [0u8; crypto_sign_PUBLICKEYBYTES as usize];
    let mut priv2 = [0u8; crypto_sign_SECRETKEYBYTES as usize];
    let result = unsafe { crypto_sign_ed25519_keypair(pub2.as_mut_ptr(), priv2.as_mut_ptr()) };

    if result != 0 {
        return Err("Failed to generate ED25519 keypair".into());
    }


    // Encrypt private keys
    let mut cpriv1 = vec![0u8; priv1.len() + crypto_secretbox_MACBYTES as usize];
    let mut cpriv2 = vec![0u8; priv2.len() + crypto_secretbox_MACBYTES as usize];

    let mut nonce1 = [0u8; crypto_secretbox_NONCEBYTES as usize];
    let mut nonce2 = [0u8; crypto_secretbox_NONCEBYTES as usize];

    // init the nonce
    unsafe { randombytes_buf(nonce1.as_mut_ptr() as *mut core::ffi::c_void, crypto_secretbox_NONCEBYTES as usize) };
    unsafe { randombytes_buf(nonce2.as_mut_ptr() as *mut core::ffi::c_void, crypto_secretbox_NONCEBYTES as usize) };

    // Encrypt the private key for encryption
    let result = unsafe {
        crypto_secretbox_easy(
            cpriv1.as_mut_ptr(),
            priv1.as_ptr(),
            priv1.len() as u64,
            nonce1.as_ptr(),
            key_array.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to encrypt private key for encryption".into());
    }

    // Encrypt the private key for signing
    let result = unsafe {
        crypto_secretbox_easy(
            cpriv2.as_mut_ptr(),
            priv2.as_ptr(),
            priv2.len() as u64,
            nonce2.as_ptr(),
            key_array.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to encrypt private key for signing".into());
    }

    srv.register(username, salt, hash, cpriv1, nonce1, pub1, cpriv2, nonce2, pub2)?;

    let fake_key = [0u8; crypto_sign_SECRETKEYBYTES as usize];
    let fake_enc_key = [0u8; crypto_box_SECRETKEYBYTES as usize];

    // TODO remove pub2
    Ok((false, "".to_string(), "".to_string(), vec![], pub1, fake_enc_key, pub2, fake_key))
}