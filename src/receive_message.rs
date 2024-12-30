use std::io;
use std::time::UNIX_EPOCH;
use inquire::Text;
use libsodium_sys::*;
use chrono::{DateTime, Local};
use num_traits::ops::bytes::ToBytes;
use std::thread;


use crate::server::Server;
use crate::user_connected::UserConnected;
use crate::consts::*;
use crate::database::Message;

///
/// Use TLS 1.3 to communicate with the client
/// Not implemented in this code
///

fn decrypt_filename(m: &Message, pub_enc_key_sender: &[u8; ENC_KEY_LEN_PUB], priv_enc_key_receiver: &[u8; ENC_KEY_LEN_PRIV]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut decrypted_filename = vec![0u8; m.filename.len() - ENC_LEN_MAC];

    let decrypt_result = unsafe {
        crypto_box_open_easy(
            decrypted_filename.as_mut_ptr(),
            m.filename.as_ptr(),
            m.filename.len() as u64,
            m.nonce_filename.as_ptr(),
            pub_enc_key_sender.as_ptr(),
            priv_enc_key_receiver.as_ptr(),
        )
    };

    if decrypt_result != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Decryption failed")));
    }

    Ok(decrypted_filename)
}

fn decrypt_message(m: &Message, pub_enc_key_sender: &[u8; ENC_KEY_LEN_PUB], priv_enc_key_receiver: &[u8; ENC_KEY_LEN_PRIV], nonce: [u8; ENC_LEN_NONCE]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut decrypted_message = vec![0u8; m.message.len() - ENC_LEN_MAC];

    let decrypt_result = unsafe {
        crypto_box_open_easy(
            decrypted_message.as_mut_ptr(),
            m.message.as_ptr(),
            m.message.len() as u64,
            nonce.as_ptr(),
            pub_enc_key_sender.as_ptr(),
            priv_enc_key_receiver.as_ptr(),
        )
    };

    if decrypt_result != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Decryption failed")));
    }

    Ok(decrypted_message)
}

fn check_signature (m: &Message, pub_sign_key_sender: &[u8; SIGN_KEY_LEN_PUB]) -> Result<(), Box<dyn std::error::Error>> {
    let mut message_to_sign = Vec::new();
    message_to_sign.extend_from_slice(&m.filename);
    message_to_sign.extend_from_slice(&m.nonce_filename);
    message_to_sign.extend_from_slice(&m.message);
    message_to_sign.extend_from_slice(m.sender.as_bytes());
    message_to_sign.extend_from_slice(m.receiver.as_bytes());
    message_to_sign.extend_from_slice(&m.delivery_time.duration_since(UNIX_EPOCH).unwrap().as_secs().to_le_bytes());
    message_to_sign.extend_from_slice(&m.delivery_time.duration_since(UNIX_EPOCH).unwrap().subsec_nanos().to_le_bytes());

    let verify_result = unsafe {
        crypto_sign_verify_detached(
            m.signature.as_ptr(),
            message_to_sign.as_ptr(),
            message_to_sign.len() as u64,
            pub_sign_key_sender.as_ptr(),
        )
    };

    if verify_result != 0 {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Invalid signature")));
    }

    Ok(())
}

// return the calculated solution [u8; ENC_LEN_NONCE]
fn solve_puzzle(m: &Message) -> Result<[u8; ENC_LEN_NONCE], Box<dyn std::error::Error>> {

    // Solve the puzzles in parallel, thread 1
    let handle1 = thread::spawn({
        let puzzle = m.puzzles[0].clone();
        let puzzle_struct = m.puzzle_struct.clone();
        move || puzzle_struct.solve(puzzle)
    });

    // thread 2
    let handle2 = thread::spawn({
        let puzzle = m.puzzles[1].clone();
        let puzzle_struct = m.puzzle_struct.clone();
        move || puzzle_struct.solve(puzzle)
    });

    // thread 3
    let handle3 = thread::spawn({
        let puzzle = m.puzzles[2].clone();
        let puzzle_struct = m.puzzle_struct.clone();
        move || puzzle_struct.solve(puzzle)
    });

    // Wait for the threads to finish
    let solution1 = handle1.join().map_err(|_| "Error solving puzzle thread 1")?;
    let solution2 = handle2.join().map_err(|_| "Error solving puzzle thread 2")?;
    let solution3 = handle3.join().map_err(|_| "Error solving puzzle thread 3")?;


    let mut nonce_message_calc = [0u8; ENC_LEN_NONCE];

    // Split the nonce_message_calc into parts corresponding to each solution
    let solution1_bytes = solution1.to_le_bytes();
    let solution2_bytes = solution2.to_le_bytes();
    let solution3_bytes = solution3.to_le_bytes();

    nonce_message_calc[..8].copy_from_slice(&solution1_bytes[..8]);
    nonce_message_calc[8..16].copy_from_slice(&solution2_bytes[..8]);
    nonce_message_calc[16..24].copy_from_slice(&solution3_bytes[..8]);

    Ok(nonce_message_calc)
}

pub fn receive_message(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {
    let username = usr.get_username();
    let messages = srv.get_messages(usr.get_mac().clone(), username)?;

    println!("{} Messages received", messages.len());


    // Create a directory if not exist to store the messages
    let path = format!("./recievedMessages/{}", username);
    std::fs::create_dir_all(&path).map_err(|e| format!("Error creating directory: {}", e))?;

    // Save the messages in the directory
    for (i, m) in messages.iter().enumerate() {

        // Check signature: filename, file, sender, recipient, timestamp
        let pub_sign_key_sender = srv.get_pub_key_sign(usr.get_username(), usr.get_mac().clone(), &m.sender).unwrap();
        match check_signature(m, &pub_sign_key_sender) {
            Ok(_) => (),
            Err(e) => {
                println!("Error checking signature: {}", e);
                continue;
            }
        }

        // Decrypt the filename
        let pub_enc_key_sender = srv.get_pub_key_enc(usr.get_username(), usr.get_mac().clone(), &m.sender).unwrap();
        let decrypted_filename = decrypt_filename(m, &pub_enc_key_sender, usr.get_priv_enc())?;
        let decrypted_filename = decrypted_filename.iter().map(|b| *b as char).collect::<String>();

        // Decrypt the message
        let mut decrypted_message = vec![0u8; m.message.len() - ENC_LEN_MAC];

        let mut nonce = m.nonce_message;

        // Check if the message can be decrypted
        if nonce == [0u8; ENC_LEN_NONCE] {
            let delivery_time: DateTime<Local> = DateTime::from(m.delivery_time);
            println!(
                "Message {} can be decrypted on {}",
                decrypted_filename,
                delivery_time.format("%Y-%m-%d %H:%M:%S") // Format lisible : Année-Mois-Jour Heure:Minute:Seconde
            );

            // ask to use time puzzle or skip
            let use_time_puzzle = Text::new("Do you want to decrypt the message locally? (yes/no)").prompt()?;
            if use_time_puzzle == "yes" {
                // Solve the puzzle
                nonce = solve_puzzle(m)?;

                println!("Successfully solved the puzzle for message {}", decrypted_filename);
            }
        }

        if nonce == [0u8; ENC_LEN_NONCE] {
            decrypted_message = m.message.clone();
            println!("Unable to decrypt message {}", decrypted_filename);

        } else {
            decrypted_message = decrypt_message(m, &pub_enc_key_sender, usr.get_priv_enc(), nonce)?;
            println!("Message {} successfully decrypted", decrypted_filename);
        }


        // Save the message in a file
        let file_path = format!("{}/{}", path, decrypted_filename);
        std::fs::write(&file_path, decrypted_message).map_err(|e| format!("Error writing file: {}", e))?;

        println!("Message {} from {} successfully writed to disk", decrypted_filename, m.sender);

    }


    Ok(())
}