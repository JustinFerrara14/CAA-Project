use inquire::Text;
use std::{fs, io};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use chrono::{Datelike, NaiveDateTime, TimeZone};
use libsodium_sys::*;

use crate::server::Server;
use crate::user_connected::UserConnected;
use crate::consts::*;

///
/// Use TLS 1.3 to communicate with the client
/// Not implemented in this code
///


fn get_recipient_pub_key(srv: &Server, usr: &UserConnected) -> Result<(String, [u8; ENC_KEY_LEN_PUB]), Box<dyn std::error::Error>> {
    loop {
        let username = Text::new("Enter the username of the recipient:")
            .prompt()?;

        if let Some(pub_key) = srv.get_pub_key_enc(usr.get_username(), usr.get_mac().clone(), &username) {
            return Ok((username, pub_key));
        } else {
            println!("Recipient not found, please try again.");
        }
    }
}

fn get_file_path() -> Result<String, io::Error> {
    loop {
        let file_path = Text::new("Enter the path to the file to send:")
            .prompt();

        if let Ok(file_path) = file_path {
            if fs::metadata(&file_path).is_ok() {
                return Ok(file_path);
            } else {
                println!("File not found, please provide a valid path.");
            }
        } else {
            println!("File not found, please provide a valid path.");
        }
    }
}

fn get_timestamp() -> Option<SystemTime> {
    loop {
        // Demander une date et heure dans le format spécifié
        let input = Text::new("Enter the date of opening (YYYY.MM.DD HH:MM):")
            .prompt();

        match input {
            Ok(datetime_str) => {
                // Valider et convertir l'entrée
                match NaiveDateTime::parse_from_str(&datetime_str, "%Y.%m.%d %H:%M") {
                    Ok(naive_dt) => {
                        // Vérifier si la date est valide en termes de calendrier
                        if naive_dt.year() < 1970 {
                            println!("Error : the year must be greater than 1970. Please try again.");
                            continue;
                        }

                        // Convertir en timestamp UNIX pour UTC+1
                        let timestamp = naive_dt.timestamp() - 3600;

                        // Convertir en SystemTime
                        let system_time = UNIX_EPOCH + Duration::from_secs(timestamp as u64);

                        println!("Date and time valid : {:?}", naive_dt);
                        return Some(system_time);
                    }
                    Err(_) => {
                        // Afficher un message d'erreur pour un format incorrect
                        println!(
                            "Error : the date and time must be in the format YYYY.MM.DD HH:MM (2012.12.31 14:00). Please try again."
                        );
                    }
                }
            }
            Err(_) => {
                // Gestion de l'annulation
                println!("Aucune valeur saisie. Annulation.");
                return None;
            }
        }
    }
}

fn encrypt_filename(file_name: Vec<u8>, pub_key_recipient: [u8; ENC_KEY_LEN_PUB], priv_enc: [u8; ENC_KEY_LEN_PRIV]) -> Result<(Vec<u8>, [u8; ENC_LEN_NONCE]), Box<dyn std::error::Error>> {
    // Generate a random nonce for the filename
    let mut nonce1 = [0u8; ENC_LEN_NONCE];
    unsafe { randombytes_buf(nonce1.as_mut_ptr() as *mut core::ffi::c_void, ENC_LEN_NONCE) };

    // Encrypt the file name with crypto_box_easy
    let mut encrypted_filename = vec![0u8; file_name.len() + ENC_LEN_MAC];
    let encrypt_result_filename = unsafe {
        crypto_box_easy(
            encrypted_filename.as_mut_ptr(),
            file_name.as_ptr(),
            file_name.len() as u64,
            nonce1.as_ptr(),
            pub_key_recipient.as_ptr(),
            priv_enc.as_ptr(),
        )
    };

    if encrypt_result_filename != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Encryption failed for filename")));
    }

    Ok((encrypted_filename, nonce1))
}

fn encrypt_file(file_content: Vec<u8>, pub_key_recipient: [u8; ENC_KEY_LEN_PUB], priv_enc: [u8; ENC_KEY_LEN_PRIV]) -> Result<(Vec<u8>, [u8; ENC_LEN_NONCE]), Box<dyn std::error::Error>> {
    // Generate a random nonce for the file
    let mut nonce2 = [0u8; ENC_LEN_NONCE];
    unsafe { randombytes_buf(nonce2.as_mut_ptr() as *mut core::ffi::c_void, ENC_LEN_NONCE) };

    // Encrypt the file with crypto_box_easy
    let mut encrypted_file = vec![0u8; file_content.len() + ENC_LEN_MAC];
    let encrypt_result_filename = unsafe {
        crypto_box_easy(
            encrypted_file.as_mut_ptr(),
            file_content.as_ptr(),
            file_content.len() as u64,
            nonce2.as_ptr(),
            pub_key_recipient.as_ptr(),
            priv_enc.as_ptr(),
        )
    };

    if encrypt_result_filename != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Encryption failed for file")));
    }

    Ok((encrypted_file, nonce2))
}

pub fn sign_message(priv_key_sender: [u8; SIGN_KEY_LEN_PRIV], encrypted_filename: Vec<u8>, nonce_filename: [u8; ENC_LEN_NONCE], encrypted_file: Vec<u8>, sender: &str, recipient: &str, timestamp: SystemTime) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Convert SystemTime to seconds and nanoseconds
    let duration_since_epoch = timestamp.duration_since(UNIX_EPOCH)
        .map_err(|_| "Time went backwards")?;
    let timestamp_seconds = duration_since_epoch.as_secs();
    let timestamp_nanos = duration_since_epoch.subsec_nanos();

    // Sign all the message: filename, file, sender, recipient, timestamp
    let mut message_to_sign = Vec::new();
    message_to_sign.extend_from_slice(&encrypted_filename);           // File name
    message_to_sign.extend_from_slice(&nonce_filename);                      // Nonce for file name
    message_to_sign.extend_from_slice(&encrypted_file);       // File content
    message_to_sign.extend_from_slice(sender.as_bytes());  // Sender username
    message_to_sign.extend_from_slice(recipient.as_bytes()); // Recipient username
    message_to_sign.extend_from_slice(&timestamp_seconds.to_le_bytes());  // Timestamp seconds
    message_to_sign.extend_from_slice(&timestamp_nanos.to_le_bytes());   // Timestamp nanoseconds

    // Sign the message
    let mut signature = vec![0u8; SIGN_LEN_SIGNATURE];
    let signing_result = unsafe {
        crypto_sign_detached(
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            message_to_sign.as_ptr(),
            message_to_sign.len() as u64,
            priv_key_sender.as_ptr(),
        )
    };

    if signing_result != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Signing failed")));
    }

    Ok(signature)
}

pub fn send_message(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {

    // Get the username of the recipient
    let (receiver, pub_key_recipient) = get_recipient_pub_key(&srv, &usr)?;

    // Get the path to the file
    let file_path = get_file_path()?;

    // Get the file name
    let file_name = file_path.split("/").last().unwrap().as_bytes().to_vec();

    // Get the timestamp
    let timestamp = get_timestamp().unwrap();

    // Read the file content
    let file_content = fs::read(&file_path)
        .map_err(|e| format!("Error reading file {}: {}", file_path, e))?;

    // Encrypt the file name
    let (encrypted_filename, nonce_filename) = encrypt_filename(file_name, pub_key_recipient, *usr.get_priv_enc())?;

    // Encrypt the file
    let (encrypted_file, nonce_file) = encrypt_file(file_content, pub_key_recipient, *usr.get_priv_enc())?;

    // signe the message
    let signature = sign_message(*usr.get_priv_sign(), encrypted_filename.clone(), nonce_filename, encrypted_file.clone(), usr.get_username(), &*receiver, timestamp)?;

    // Send the file to the server
    // TODO change
    srv.send_message(usr.get_mac().clone(), usr.get_username(), &*receiver, timestamp, encrypted_filename, nonce_filename, encrypted_file, nonce_file, signature)?;

    println!("Message sent successfully");

    Ok(())
}