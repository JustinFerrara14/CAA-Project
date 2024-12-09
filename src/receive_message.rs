use std::io;
use std::time::UNIX_EPOCH;
use inquire::Text;
use libsodium_sys::*;
use chrono::{DateTime, Local};
use lhtlp::LHTLP;
use num_bigint::BigUint;
use num_traits::ops::bytes::ToBytes;


use crate::server::Server;
use crate::user_connected::UserConnected;

const LAMBDA: u64 = 256;

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
            let delivery_time: DateTime<Local> = DateTime::from(m.delivery_time);
            println!(
                "Message {} can be decrypted on {}",
                decrypted_filename.iter().map(|b| *b as char).collect::<String>(),
                delivery_time.format("%Y-%m-%d %H:%M:%S") // Format lisible : Année-Mois-Jour Heure:Minute:Seconde
            );

            // ask to use time puzzle or skip
            let use_time_puzzle = Text::new("Do you want to decrypt the message now? (yes/no)").prompt()?;
            if use_time_puzzle == "no" {
                decrypted_message = m.message.clone();
                continue;
            }


            // println!("puzzle complexity: {}", m.puzzle_complexity);
            // let lhtlp = LHTLP::setup(LAMBDA, BigUint::from(m.puzzle_complexity));

            let solution1 = m.puzzle_complexity.solve(m.puzzles[0].clone());
            let solution2 =  m.puzzle_complexity.solve(m.puzzles[1].clone());
            let solution3 =  m.puzzle_complexity.solve(m.puzzles[2].clone());

            let mut nonce_message_calc = [0u8; crypto_box_NONCEBYTES as usize];

            // Split the nonce_message_calc into parts corresponding to each solution
            let solution1_bytes = solution1.to_le_bytes();
            let solution2_bytes = solution2.to_le_bytes();
            let solution3_bytes = solution3.to_le_bytes();

            nonce_message_calc[..8].copy_from_slice(&solution1_bytes[..8]);
            nonce_message_calc[8..16].copy_from_slice(&solution2_bytes[..8]);
            nonce_message_calc[16..24].copy_from_slice(&solution3_bytes[..8]);

            let decrypt_result_file = unsafe {
                crypto_box_open_easy(
                    decrypted_message.as_mut_ptr(),
                    m.message.as_ptr(),
                    m.message.len() as u64,
                    nonce_message_calc.as_ptr(),
                    pub_enc_key_sender.as_ptr(),
                    usr.get_priv1().as_ptr(),
                )
            };

            if decrypt_result_file != 0 {
                return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Encryption failed")));
            }

            println!("Message {} successfully decrypted with time puzzle", decrypted_filename.iter().map(|b| *b as char).collect::<String>());

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

            println!("Message {} successfully decrypted", decrypted_filename.iter().map(|b| *b as char).collect::<String>());
        }


        // Save the message in a file
        let file_path = format!("{}/{}", path, decrypted_filename.iter().map(|b| *b as char).collect::<String>());
        std::fs::write(&file_path, decrypted_message).map_err(|e| format!("Error writing file: {}", e))?;

        println!("Message {} successfully writed to disk", decrypted_filename.iter().map(|b| *b as char).collect::<String>());

    }


    Ok(())
}