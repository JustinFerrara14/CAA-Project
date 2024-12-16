use inquire::Text;
use std::io;
use generic_array::GenericArray;
use generic_array::typenum::U64;
use libsodium_sys::*;

use crate::server::Server;
use crate::server::DefaultCipherSuite;
use crate::user_connected::UserConnected;
use crate::consts::*;

use opaque_ke::*;
use rand::rngs::OsRng;

fn calculate_mac(username: &str, key_communication: Vec<u8>) -> Result<[u8; MAC_LEN], Box<dyn std::error::Error>> {
    let mut mac = [0u8; MAC_LEN];

    let result = unsafe {
        crypto_auth(
            mac.as_mut_ptr(),
            username.as_ptr(),
            username.len() as u64,
            key_communication.as_ptr(),
        )
    };

    if result != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "MAC invalid")));
    }

    Ok(mac)
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
    let result = unsafe { crypto_sign_keypair(pub2.as_mut_ptr(), priv2.as_mut_ptr()) };

    if result != 0 {
        return Err("Failed to generate ED25519 keypair".into());
    }

    // Encrypt private keys
    let (nonce1, cpriv1, nonce2, cpriv2) = enc_key(&priv1.to_vec(), &priv2.to_vec(), key)?;


    Ok((pub1, nonce1, cpriv1, pub2, nonce2, cpriv2))
}


pub fn register(srv: &mut Server) -> Result<(), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let password_confirm = Text::new("Confirm your password:").prompt()?;

    if password != password_confirm {
        println!("Passwords do not match");
        // return error
        return Err("Passwords do not match".into());
    }

    // Generate key with OPAQUE
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes()).map_err(|e| e.to_string())?;

    let server_registration_start_result = srv.server_registration_start(&username, client_registration_start_result.clone())?;

    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        password.as_bytes(),
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    ).map_err(|e| e.to_string())?;

    let key = client_registration_finish_result.export_key.clone();
    let key: Vec<u8> = key.to_vec();

    // Check if key has the minimum length
    if key.len() < HASH_LEN_KEY {
        return Err("Error in key generation".into());
    }

    // troncate the key to HASH_LEN_KEY
    let key = key[..HASH_LEN_KEY].to_vec();

    // generate asym keys
    let (pub1, nonce1, cpriv1, pub2, nonce2, cpriv2) = generate_asym_key(&key)?;

    srv.server_registration_finish(client_registration_finish_result, &username, cpriv1, nonce1, pub1, cpriv2, nonce2, pub2)?;

    Ok(())
}

/// return connected: username: String, h: String, k: Vec<u8>, pub1: PublicKey, priv1: SecretKey, pub2: PublicKey, priv2: SecretKey,
pub fn login(srv: &mut Server) -> Result<(String, Vec<u8>, GenericArray<u8, U64>, [u8; MAC_LEN], [u8; ENC_KEY_LEN_PUB], [u8; ENC_KEY_LEN_PRIV], [u8; SIGN_KEY_LEN_PUB], [u8; SIGN_KEY_LEN_PRIV]), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;

    let mut client_rng = OsRng;
    let client_login_start_result = ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes()).map_err(|e| e.to_string())?;

    let server_login_start_result = srv.server_login_start(&username, client_login_start_result.clone())?;

    let client_login_finish_result = client_login_start_result.state.finish(
        password.as_bytes(),
        server_login_start_result.message.clone(),
        ClientLoginFinishParameters::default(),
    ).map_err(|e| e.to_string())?;


    let key = client_login_finish_result.export_key.clone();
    let key: Vec<u8> = key.to_vec();
    // troncate the key to HASH_LEN_KEY
    let key = key[..HASH_LEN_KEY].to_vec();
    let key_communication = client_login_finish_result.session_key.clone();

    let (pub1, cpriv1, nonce1, pub2, cpriv2, nonce2) = srv.server_login_finish(&username, server_login_start_result, client_login_finish_result)?;

    // Recorver the private key
    let (priv1, priv2) = dec_key(&cpriv1, &cpriv2, &key, nonce1, nonce2)?;

    // Calculate the mac
    let mac = calculate_mac(&username, key_communication.to_vec())?;

    Ok((username, key.to_vec(), key_communication, mac, pub1, priv1, pub2, priv2))
}

pub fn logout(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {
    srv.logout(&usr.get_username(), usr.get_mac().clone())?;
    Ok(())
}

pub fn change_password(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {

    let password = Text::new("Enter your new password:").prompt()?;
    let password_confirm = Text::new("Confirm your new password:").prompt()?;

    if password != password_confirm {
        println!("Passwords do not match");
        // return error
        return Err("Passwords do not match".into());
    }


    // Generate key with OPAQUE
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes()).map_err(|e| e.to_string())?;

    let server_registration_start_result = srv.server_registration_start(&usr.get_username(), client_registration_start_result.clone())?;

    let client_registration_finish_result = client_registration_start_result.state.finish(
        &mut client_rng,
        password.as_bytes(),
        server_registration_start_result.message,
        ClientRegistrationFinishParameters::default(),
    ).map_err(|e| e.to_string())?;

    let new_key = client_registration_finish_result.export_key.clone();
    let new_key: Vec<u8> = new_key.to_vec();

    // Encrypt private keys
    let (new_nonce1, cpriv1, new_nonce2, cpriv2) = enc_key(&usr.get_priv_enc().to_vec(), &usr.get_priv_sign().to_vec(), &new_key)?;

    srv.server_registration_finish_update(client_registration_finish_result, usr.get_username(), usr.get_mac().clone(), cpriv1, new_nonce1, *usr.get_pub_enc(), cpriv2, new_nonce2, *usr.get_pub_sign())?;

    Ok(())
}