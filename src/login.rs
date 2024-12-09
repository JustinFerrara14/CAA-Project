use inquire::Text;
use std::ffi::*;
use libsodium_sys::*;

use crate::server::Server;
use crate::user_connected::UserConnected;

/// return connected: bool, username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn login(srv: &mut Server) -> Result<(bool, String, String, Vec<u8>, [u8; crypto_box_PUBLICKEYBYTES as usize], [u8; crypto_box_SECRETKEYBYTES as usize], [u8; crypto_sign_PUBLICKEYBYTES as usize], [u8; crypto_sign_SECRETKEYBYTES as usize]), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;

    let salt = srv.get_salt(&username).ok_or("User not found")?;

    const HASH_LEN: usize = 96;
    let mut password_hash = [0u8; HASH_LEN];

    // Hash the password
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
    let hash = hex::encode(&password_hash[..64]);
    let key_array: [u8; 32] = password_hash[64..].try_into().expect("Slice with incorrect length");


    let (pub1, cpriv1, nonce1, pub2, cpriv2, nonce2) = srv.login(&username, &hash)?;

    // Recorver the private key
    let mut priv1 = [0u8; crypto_box_SECRETKEYBYTES as usize];
    let mut priv2 = [0u8; crypto_sign_SECRETKEYBYTES as usize];


    let result = unsafe {
        crypto_secretbox_open_easy(
            priv1.as_mut_ptr(),
            cpriv1.as_ptr(),
            cpriv1.len() as u64,
            nonce1.as_ptr(),
            key_array.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to decrypt private key".into());
    }

    let result = unsafe {
        crypto_secretbox_open_easy(
            priv2.as_mut_ptr(),
            cpriv2.as_ptr(),
            cpriv2.len() as u64,
            nonce2.as_ptr(),
            key_array.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to decrypt private key".into());
    }

    Ok((true, username, hash, key_array.to_vec(), pub1, priv1, pub2, priv2))
}

pub fn change_password(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {

    let password = Text::new("Enter your new password:").prompt()?;
    let password_confirm = Text::new("Confirm your new password:").prompt()?;

    if password != password_confirm {
        println!("Passwords do not match");
        // return error
        return Err("Passwords do not match".into());
    }

    // Générer un nouveau sel
    let mut new_salt = [0u8; crypto_pwhash_SALTBYTES as usize];
    unsafe { randombytes_buf(new_salt.as_mut_ptr() as *mut core::ffi::c_void, crypto_pwhash_SALTBYTES as usize) };

    const HASH_LEN: usize = 96;
    let mut new_password_hash = [0u8; HASH_LEN];

    // Hash du nouveau mot de passe avec Libsodium
    let result = unsafe {
        crypto_pwhash(
            new_password_hash.as_mut_ptr(),
            HASH_LEN as u64,
            password.as_ptr() as *const i8,
            password.len() as u64,
            new_salt.as_ptr(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE as c_ulonglong,
            crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
            crypto_pwhash_ALG_ARGON2ID13 as c_int,
        )
    };

    if result != 0 {
        return Err("Failed to hash new password using libsodium".into());
    }

    // Séparer le hash et la clé
    let new_hash = hex::encode(&new_password_hash[..64]);
    let new_key_array: [u8; 32] = new_password_hash[64..].try_into().expect("Slice with incorrect length");


    // Encrypt private keys
    let mut cpriv1 = vec![0u8; usr.get_priv1().len() + crypto_secretbox_MACBYTES as usize];
    let mut cpriv2 = vec![0u8; usr.get_priv2().len() + crypto_secretbox_MACBYTES as usize];

    let mut new_nonce1 = [0u8; crypto_secretbox_NONCEBYTES as usize];
    let mut new_nonce2 = [0u8; crypto_secretbox_NONCEBYTES as usize];

    // init the nonce
    unsafe { randombytes_buf(new_nonce1.as_mut_ptr() as *mut core::ffi::c_void, crypto_secretbox_NONCEBYTES as usize) };
    unsafe { randombytes_buf(new_nonce1.as_mut_ptr() as *mut core::ffi::c_void, crypto_secretbox_NONCEBYTES as usize) };

    // Encrypt the private key for encryption
    let result = unsafe {
        crypto_secretbox_easy(
            cpriv1.as_mut_ptr(),
            usr.get_priv1().as_ptr(),
            usr.get_priv1().len() as u64,
            new_nonce1.as_ptr(),
            new_key_array.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to encrypt private key for encryption".into());
    }

    // Encrypt the private key for signing
    let result = unsafe {
        crypto_secretbox_easy(
            cpriv2.as_mut_ptr(),
            usr.get_priv2().as_ptr(),
            usr.get_priv2().len() as u64,
            new_nonce2.as_ptr(),
            new_key_array.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to encrypt private key for signing".into());
    }

    srv.change_password(usr.get_username().parse().unwrap(), usr.get_h().parse().unwrap(), new_salt, new_hash, cpriv1, new_nonce1, *usr.get_pub1(), cpriv2, new_nonce2, *usr.get_pub2())?;

    Ok(())
}