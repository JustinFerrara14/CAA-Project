use inquire::Text;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use libsodium_sys::*;

use crate::server::Server;
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

    let (pub1, cpriv1, nonce1, pub2, cpriv2, nonce2) = srv.login(&username, &hash)?;

    // Recorver the private key
    let mut priv1 = [0u8; crypto_box_SECRETKEYBYTES as usize];
    let mut priv2 = [0u8; crypto_sign_SECRETKEYBYTES as usize];

    println!("len priv2 : {}", priv2.len());
    println!("len cpriv2 : {}", cpriv2.len());

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