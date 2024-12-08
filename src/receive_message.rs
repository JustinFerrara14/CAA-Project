use std::io;
use std::time::UNIX_EPOCH;
use inquire::Text;
use libsodium_sys::*;
use chrono::{DateTime, Local};

use crate::server::Server;
use crate::user_connected::UserConnected;


pub fn receive_message(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {
    let username = usr.get_username();
    let messages = srv.get_messages(usr.get_h().parse().unwrap(), username);

    println!("Messages received");


    // Create a directory if not exist to store the messages
    let path = format!("./recievedMessages/{}", username);
    std::fs::create_dir_all(&path).map_err(|e| format!("Error creating directory: {}", e))?;

    // Save the messages in the directory
    for (i, m) in messages?.iter().enumerate() {

        // Convert SystemTime to seconds and nanoseconds
        let duration_since_epoch = m.delivery_time.duration_since(UNIX_EPOCH)
            .map_err(|_| "Time went backwards")?;
        let timestamp_seconds = duration_since_epoch.as_secs();
        let timestamp_nanos = duration_since_epoch.subsec_nanos();

        // Check signature: filename, file, sender, recipient, timestamp
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&m.filename);
        message_to_sign.extend_from_slice(&m.nonce_filename);
        message_to_sign.extend_from_slice(&m.message);
        message_to_sign.extend_from_slice(&m.nonce_message);
        message_to_sign.extend_from_slice(m.sender.as_bytes());
        message_to_sign.extend_from_slice(m.receiver.as_bytes());
        message_to_sign.extend_from_slice(&timestamp_seconds.to_le_bytes());
        message_to_sign.extend_from_slice(&timestamp_nanos.to_le_bytes());

        // Verify the signature
        let pub_sign_key_sender = srv.get_pub_key2(&m.sender).unwrap();

        let verify_result = unsafe {
            crypto_sign_ed25519_verify_detached(
                m.signature.as_ptr(),
                message_to_sign.as_ptr(),
                message_to_sign.len() as u64,
                pub_sign_key_sender.as_ptr(),
            )
        };

        if verify_result != 0 {
            println!("Invalid signature for message {}", i);

            if m.nonce_message == [0u8; crypto_box_NONCEBYTES as usize] {
                println!("Invalid signature might be due to the message being sent in the future");
            } else {
                continue;
            }
        }

        let pub_enc_key_sender = srv.get_pub_key1(&m.sender).unwrap();

        // Decrypt the filename
        let mut decrypted_filename = vec![0u8; m.filename.len() - crypto_box_MACBYTES as usize];
        let decrypt_result_filename = unsafe {
            crypto_box_open_easy(
                decrypted_filename.as_mut_ptr(),
                m.filename.as_ptr(),
                m.filename.len() as u64,
                m.nonce_filename.as_ptr(),
                pub_enc_key_sender.as_ptr(),
                usr.get_priv1().as_ptr(),
            )
        };

        if decrypt_result_filename != 0 {
            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Decryption failed")));
        }

        // Decrypt the message
        let mut decrypted_message = vec![0u8; m.message.len() - crypto_box_MACBYTES as usize];


        if m.nonce_message == [0u8; crypto_box_NONCEBYTES as usize] {
            decrypted_message = m.message.clone();
            let delivery_time: DateTime<Local> = DateTime::from(m.delivery_time);
            println!(
                "Message {} can be decrypted on {}",
                decrypted_filename.iter().map(|b| *b as char).collect::<String>(),
                delivery_time.format("%Y-%m-%d %H:%M:%S") // Format lisible : Année-Mois-Jour Heure:Minute:Seconde
            );

        } else {
            let decrypt_result_file = unsafe {
                crypto_box_open_easy(
                    decrypted_message.as_mut_ptr(),
                    m.message.as_ptr(),
                    m.message.len() as u64,
                    m.nonce_message.as_ptr(),
                    pub_enc_key_sender.as_ptr(),
                    usr.get_priv1().as_ptr(),
                )
            };

            if decrypt_result_file != 0 {
                return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Encryption failed")));
            }
        }


        // Save the message in a file
        let file_path = format!("{}/{}", path, decrypted_filename.iter().map(|b| *b as char).collect::<String>());
        std::fs::write(&file_path, decrypted_message).map_err(|e| format!("Error writing file: {}", e))?;

        println!("Message {} successfully received", decrypted_filename.iter().map(|b| *b as char).collect::<String>());

    }


    Ok(())
}