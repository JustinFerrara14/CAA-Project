use inquire::Text;
use std::ffi::*;
use libsodium_sys::*;

use crate::server::Server;
use crate::user_connected::UserConnected;
use crate::consts::*;

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    unsafe {
        randombytes_buf(salt.as_mut_ptr() as *mut core::ffi::c_void, SALT_LEN);
    }
    salt
}

fn generate_h_k(password: &str, salt: &[u8; SALT_LEN]) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let mut password_hash = [0u8; HASH_LEN];

    // Generate the password hash using Libsodium's crypto_pwhash
    // TODO calculate parameters for OPSLIMIT and MEMLIMIT
    let result = unsafe {
        crypto_pwhash(
            password_hash.as_mut_ptr(),
            HASH_LEN as u64,
            password.as_ptr() as *const i8,
            password.len() as u64,
            salt.as_ptr(),
            OPSLIMIT,
            MEMLIMIT,
            ALG,
        )
    };

    if result != 0 {
        return Err("Failed to hash password using libsodium".into());
    }

    // Extract key material and hash
    let hash = hex::encode(&password_hash[..HASH_LEN_HASH]); // First 64 bytes for the hash
    let key = password_hash[HASH_LEN_HASH..].try_into().expect("Slice with incorrect length");

    Ok((hash, key))
}

// encrypt priv1 and priv2 with key to get nonce1, cpriv1, nonce2, cpriv2
fn enc_key(priv1: &Vec<u8>, priv2: &Vec<u8>, key: &Vec<u8>) -> Result<([u8; SYM_LEN_NONCE], Vec<u8>, [u8; SYM_LEN_NONCE], Vec<u8>), Box<dyn std::error::Error>> {
    let mut cpriv1 = vec![0u8; priv1.len() + SYM_LEN_MAC];
    let mut cpriv2 = vec![0u8; priv2.len() + SYM_LEN_MAC];

    let mut nonce1 = [0u8; SYM_LEN_NONCE];
    let mut nonce2 = [0u8; SYM_LEN_NONCE];

    // init the nonce
    unsafe { randombytes_buf(nonce1.as_mut_ptr() as *mut core::ffi::c_void, SYM_LEN_NONCE) };
    unsafe { randombytes_buf(nonce2.as_mut_ptr() as *mut core::ffi::c_void, SYM_LEN_NONCE) };

    // Encrypt the private key for encryption
    let result = unsafe {
        crypto_secretbox_easy(
            cpriv1.as_mut_ptr(),
            priv1.as_ptr(),
            priv1.len() as u64,
            nonce1.as_ptr(),
            key.as_ptr(),
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
            key.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to encrypt private key for signing".into());
    }

    Ok((nonce1, cpriv1, nonce2, cpriv2))
}

// decrypt cpriv1 and cpriv2 with key to get priv1 and priv2
fn dec_key(cpriv1: &Vec<u8>, cpriv2: &Vec<u8>, key: &Vec<u8>, nonce1: [u8; SYM_LEN_NONCE], nonce2: [u8; SYM_LEN_NONCE]) -> Result<([u8; ENC_KEY_LEN_PRIV], [u8; SIGN_KEY_LEN_PRIV]), Box<dyn std::error::Error>> {
    let mut priv1 = [0u8; ENC_KEY_LEN_PRIV ];
    let mut priv2 = [0u8; SIGN_KEY_LEN_PRIV];

    // Decrypt the private key for encryption
    let result = unsafe {
        crypto_secretbox_open_easy(
            priv1.as_mut_ptr(),
            cpriv1.as_ptr(),
            cpriv1.len() as u64,
            nonce1.as_ptr(),
            key.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to decrypt private key for encryption".into());
    }

    // Decrypt the private key for signing
    let result = unsafe {
        crypto_secretbox_open_easy(
            priv2.as_mut_ptr(),
            cpriv2.as_ptr(),
            cpriv2.len() as u64,
            nonce2.as_ptr(),
            key.as_ptr(),
        )
    };

    if result != 0 {
        return Err("Failed to decrypt private key for signing".into());
    }

    Ok((priv1, priv2))
}

// generate 2 pairs of asym key for singing and enc, return pub1, nonce1, cpriv1, pub2, nonce2, cpriv2
fn generate_asym_key(key: &Vec<u8>) -> Result<([u8; ENC_KEY_LEN_PUB], [u8; SYM_LEN_NONCE], Vec<u8>, [u8; SIGN_KEY_LEN_PUB], [u8; SYM_LEN_NONCE], Vec<u8>), Box<dyn std::error::Error>> {

    // Key for encryption
    let mut pub1 = [0u8; ENC_KEY_LEN_PUB];
    let mut priv1 = [0u8; ENC_KEY_LEN_PRIV];
    let result = unsafe { crypto_box_keypair(pub1.as_mut_ptr(), priv1.as_mut_ptr()) };

    if result != 0 {
        return Err("Failed to generate encryption keypair".into());
    }

    // Key for signing using ed25519 crypto_sign_ed25519_keypair
    let mut pub2 = [0u8; SIGN_KEY_LEN_PUB];
    let mut priv2 = [0u8; SIGN_KEY_LEN_PRIV];
    let result = unsafe { crypto_sign_ed25519_keypair(pub2.as_mut_ptr(), priv2.as_mut_ptr()) };

    if result != 0 {
        return Err("Failed to generate ED25519 keypair".into());
    }

    // Encrypt private keys
    let (nonce1, cpriv1, nonce2, cpriv2) = enc_key(&priv1.to_vec(), &priv2.to_vec(), key)?;


    Ok((pub1, nonce1, cpriv1, pub2, nonce2, cpriv2))
}

/// return connected: bool, username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn register(srv: &mut Server) -> Result<(bool, String, String, Vec<u8>, [u8; ENC_KEY_LEN_PUB], [u8; ENC_KEY_LEN_PRIV], [u8; SIGN_KEY_LEN_PUB], [u8; SIGN_KEY_LEN_PRIV]), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let password_confirm = Text::new("Confirm your password:").prompt()?;

    if password != password_confirm {
        println!("Passwords do not match");
        // return error
        return Err("Passwords do not match".into());
    }

    let salt = generate_salt();
    let (hash, key) = generate_h_k(&password, &salt)?;

    // generate asym keys
    let (pub1, nonce1, cpriv1, pub2, nonce2, cpriv2) = generate_asym_key(&key)?;

    srv.register(username, salt, hash, cpriv1, nonce1, pub1, cpriv2, nonce2, pub2)?;

    // TODO change
    let fake_key = [0u8; SIGN_KEY_LEN_PRIV];
    let fake_enc_key = [0u8; ENC_KEY_LEN_PRIV];

    // TODO remove pub2
    Ok((false, "".to_string(), "".to_string(), vec![], pub1, fake_enc_key, pub2, fake_key))
}

/// return connected: bool, username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn login(srv: &mut Server) -> Result<(bool, String, String, Vec<u8>, [u8; ENC_KEY_LEN_PUB], [u8; ENC_KEY_LEN_PRIV], [u8; SIGN_KEY_LEN_PUB], [u8; SIGN_KEY_LEN_PRIV]), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;

    let salt = srv.get_salt(&username).ok_or("User not found")?;

    let (hash, key) = generate_h_k(&password, &salt)?;


    let (pub1, cpriv1, nonce1, pub2, cpriv2, nonce2) = srv.login(&username, &hash)?;

    // Recorver the private key
    let (priv1, priv2) = dec_key(&cpriv1, &cpriv2, &key, nonce1, nonce2)?;

    Ok((true, username, hash, key.to_vec(), pub1, priv1, pub2, priv2))
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
    let new_salt = generate_salt();

    // Générer un nouveau hash et clé
    let (new_hash, new_key) = generate_h_k(&password, &new_salt)?;

    // Encrypt private keys
    let (new_nonce1, cpriv1, new_nonce2, cpriv2) = enc_key(&usr.get_priv_enc().to_vec(), &usr.get_priv_sign().to_vec(), &new_key)?;

    srv.change_password(usr.get_username().parse().unwrap(), usr.get_h().parse().unwrap(), new_salt, new_hash, cpriv1, new_nonce1, *usr.get_pub_enc(), cpriv2, new_nonce2, *usr.get_pub_sign())?;

    Ok(())
}