use inquire::Text;
use ecies::{SecretKey, PublicKey, encrypt};
use ed25519::signature::{Signer, Verifier};
use std::{fs, io};
use std::time::SystemTime;
use crate::server::Server;
use crate::user_connected::UserConnected;


fn get_recipient_pub_key(srv: &Server) -> Result<(String, [u8; 65]), Box<dyn std::error::Error>> {
    loop {
        let username = Text::new("Enter the username of the recipient:")
            .prompt()?;

        if let Some(pub_key) = srv.get_pub_key(&username) {
            return Ok((username, pub_key.serialize()));
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

fn get_timestamp() -> SystemTime {
    // Ask the user for the timestamp
    let timestamp = Text::new("Enter the timestamp:")
        .prompt()
        .unwrap();

    // Convert the timestamp to a SystemTime
    let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp.parse().unwrap());

    timestamp
}

pub fn send_message(srv: &mut Server, usr: &UserConnected) -> Result<(), Box<dyn std::error::Error>> {

    // Get the username of the recipient
    let (username, pub_key_recipient) = get_recipient_pub_key(&srv)?;

    // Get the path to the file
    let file_path = get_file_path()?;

    // Get the file name
    let file_name = file_path.split("/").last().unwrap().as_bytes().to_vec();

    // Get the timestamp
    let timestamp = get_timestamp();

    // Read the file content
    let file_content = fs::read(&file_path)
        .map_err(|e| format!("Error reading file {}: {}", file_path, e))?;

    // Encrypt the file with ecies
    let encrypted_filename = encrypt(&pub_key_recipient, &file_name).map_err(|e| format!("Encryption error: {}", e))?;
    let encrypted_file = encrypt(&pub_key_recipient, &file_content).map_err(|e| format!("Encryption error: {}", e))?;

    // Sign all the message: filename, file and timestamp
    let signature = usr.get_priv2().Signer().sign(&[&encrypted_filename, &encrypted_file, &timestamp.to_string().as_bytes()]);

    // Send the file to the server
    srv.send_message(usr.get_h().parse().unwrap(), usr.get_username(), &*username, encrypted_filename, encrypted_file, signature)?;

    Ok(())
}