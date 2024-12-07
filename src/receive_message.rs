use inquire::Text;
use ecies::{SecretKey, PublicKey, encrypt, decrypt};

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

        let (filename_encrypted, message_encrypted) = m;

        // Decrypt the filename
        let decrypted_filename = decrypt(&usr.get_priv1().serialize(), filename_encrypted).map_err(|e| format!("Decryption error: {}", e))?;

        // Decrypt the message
        let decrypted_message = decrypt(&usr.get_priv1().serialize(), message_encrypted).map_err(|e| format!("Decryption error: {}", e))?;

        // Save the message in a file
        let file_path = format!("{}/{}", path, decrypted_filename.iter().map(|b| *b as char).collect::<String>());
        std::fs::write(&file_path, decrypted_message).map_err(|e| format!("Error writing file: {}", e))?;

    }


    Ok(())
}