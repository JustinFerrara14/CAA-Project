use inquire::Text;
use std::{fs, io};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use chrono::{Datelike, NaiveDateTime, TimeZone, Utc};
use libsodium_sys::*;
use crate::server::Server;
use crate::user_connected::UserConnected;


fn get_recipient_pub_key(srv: &Server) -> Result<(String, [u8; crypto_box_PUBLICKEYBYTES as usize]), Box<dyn std::error::Error>> {
    loop {
        let username = Text::new("Enter the username of the recipient:")
            .prompt()?;

        if let Some(pub_key) = srv.get_pub_key1(&username) {
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
        let input = Text::new("Enter the date of opening (YYYY:MM:DD HH:MM):")
            .prompt();

        match input {
            Ok(datetime_str) => {
                // Valider et convertir l'entrée
                match NaiveDateTime::parse_from_str(&datetime_str, "%Y:%m:%d %H:%M") {
                    Ok(naive_dt) => {
                        // Vérifier si la date est valide en termes de calendrier
                        if naive_dt.year() < 1970 {
                            println!("Erreur : l'année doit être 1970 ou plus.");
                            continue;
                        }

                        // Convertir en timestamp UNIX pour UTC+1
                        let timestamp = naive_dt.timestamp() - 3600;

                        // Convertir en SystemTime
                        let system_time = UNIX_EPOCH + Duration::from_secs(timestamp as u64);

                        println!("Date et heure valides : {}", naive_dt);
                        return Some(system_time);
                    }
                    Err(err) => {
                        // Afficher un message d'erreur pour un format incorrect
                        println!(
                            "Erreur : le format doit être YYYY:MM:DD HH:MM (par ex. 2024:12:08 15:30). Veuillez réessayer."
                        );
                        println!("Détails de l'erreur : {}", err);
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
pub fn send_message(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {

    // Get the username of the recipient
    let (username, pub_key_recipient) = get_recipient_pub_key(&srv)?;

    // Get the path to the file
    let file_path = get_file_path()?;

    // Get the file name
    let file_name = file_path.split("/").last().unwrap().as_bytes().to_vec();

    // Get the timestamp
    let timestamp = get_timestamp().unwrap();

    // Read the file content
    let file_content = fs::read(&file_path)
        .map_err(|e| format!("Error reading file {}: {}", file_path, e))?;

    // Generate a random nonce for the filename
    let mut nonce1 = [0u8; crypto_box_NONCEBYTES as usize];
    unsafe { randombytes_buf(nonce1.as_mut_ptr() as *mut core::ffi::c_void, crypto_box_NONCEBYTES as usize) };


    // Encrypt the file name with crypto_box_easy
    let mut encrypted_filename = vec![0u8; file_name.len() + crypto_box_MACBYTES as usize];
    let encrypt_result_filename = unsafe {
        crypto_box_easy(
            encrypted_filename.as_mut_ptr(),
            file_name.as_ptr(),
            file_name.len() as u64,
            nonce1.as_ptr(),
            pub_key_recipient.as_ptr(),
            usr.get_priv1().as_ptr(),
        )
    };

    if encrypt_result_filename != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Encryption failed for filename")));
    }


    // Generate a random nonce for the file
    let mut nonce2 = [0u8; crypto_box_NONCEBYTES as usize];
    unsafe { randombytes_buf(nonce2.as_mut_ptr() as *mut core::ffi::c_void, crypto_box_NONCEBYTES as usize) };

    // Encrypt the file with crypto_box_easy
    let mut encrypted_file = vec![0u8; file_content.len() + crypto_box_MACBYTES as usize];
    let encrypt_result_filename = unsafe {
        crypto_box_easy(
            encrypted_file.as_mut_ptr(),
            file_content.as_ptr(),
            file_content.len() as u64,
            nonce2.as_ptr(),
            pub_key_recipient.as_ptr(),
            usr.get_priv1().as_ptr(),
        )
    };

    if encrypt_result_filename != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Encryption failed for file")));
    }


    // Convert SystemTime to seconds and nanoseconds
    let duration_since_epoch = timestamp.duration_since(UNIX_EPOCH)
        .map_err(|_| "Time went backwards")?;
    let timestamp_seconds = duration_since_epoch.as_secs();
    let timestamp_nanos = duration_since_epoch.subsec_nanos();


    // Sign all the message: filename, file, sender, recipient, timestamp
    let mut message_to_sign = Vec::new();
    message_to_sign.extend_from_slice(&encrypted_filename);           // File name
    message_to_sign.extend_from_slice(&nonce1);                      // Nonce for file name
    message_to_sign.extend_from_slice(&encrypted_file);       // File content
    message_to_sign.extend_from_slice(&nonce2);                      // Nonce for file content
    message_to_sign.extend_from_slice(usr.get_username().as_bytes());  // Sender username
    message_to_sign.extend_from_slice(&username.as_bytes()); // Recipient username
    message_to_sign.extend_from_slice(&timestamp_seconds.to_le_bytes());  // Timestamp seconds
    message_to_sign.extend_from_slice(&timestamp_nanos.to_le_bytes());   // Timestamp nanoseconds


    // Get the secret key of the sender
    let secret_key = usr.get_priv2();

    // Sign the message using crypto_sign_ed25519
    let mut signature = vec![0u8; crypto_sign_ed25519_BYTES as usize];
    let signing_result = unsafe {
        crypto_sign_ed25519_detached(
            signature.as_mut_ptr(),
            std::ptr::null_mut(),
            message_to_sign.as_ptr(),
            message_to_sign.len() as u64,
            secret_key.as_ptr(),
        )
    };

    if signing_result != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Signing failed")));
    }

    // Send the file to the server
    srv.send_message(usr.get_h().parse().unwrap(), usr.get_username(), &*username, timestamp, encrypted_filename, nonce1, encrypted_file, nonce2, signature)?;

    println!("Message sent successfully");

    Ok(())
}