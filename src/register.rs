use libsodium_sys::*;
use inquire::Text;
use std::ffi::*;
use crate::server::Server;

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

    const HASH_LEN: usize = 96; // Output length for password hash
    let mut password_hash = [0u8; HASH_LEN];
    let mut salt = [0u8; crypto_pwhash_SALTBYTES as usize];

    // Generate salt
    unsafe {
        randombytes_buf(salt.as_mut_ptr() as *mut core::ffi::c_void, crypto_pwhash_SALTBYTES as usize);
    }

    // Generate the password hash using Libsodium's crypto_pwhash
    // TODO calculate parameters for OPSLIMIT and MEMLIMIT
    let result = unsafe {
        crypto_pwhash(
            password_hash.as_mut_ptr(),
            HASH_LEN as u64,
            password.as_ptr() as *const i8,
            password.len() as u64,
            salt.as_ptr(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE as c_ulonglong,
            crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
            crypto_pwhash_ALG_ARGON2ID13 as c_int,
        )
    };

    if result != 0 {
        return Err("Failed to hash password using libsodium".into());
    }

    // Extract key material and hash
    let hash = hex::encode(&password_hash[..64]); // First 64 bytes for the hash
    let key_hex = hex::encode(&password_hash[64..]); // Last 32 bytes for the encryption key
    let key = hex::decode(key_hex)?;
    let key_array: [u8; 32] = key[..32].try_into().expect("Slice with incorrect length");


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