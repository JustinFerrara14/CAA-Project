mod login;
mod database;
mod server;
mod send_message;
mod receive_message;
mod user_connected;
mod consts;

use inquire::{Text, Select};
use user_connected::UserConnected;
use crate::server::Server;
use libsodium_sys::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Initialize libsodium
    if unsafe { sodium_init() } == -1 {
        panic!("libsodium init failed");
    }


    let mut srv = server::Server::new();

    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["login", "register", "exit"])
            .prompt()?;

        let result = match select {
            "login" => login::login(&mut srv),
            "register" => login::register(&mut srv),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

        match result {
            Ok((connected, username, key, key_communication, mac, pub1, priv1, pub2, priv2)) => {
                if connected {
                    let user = UserConnected::new(connected, username, key, key_communication, mac, pub1, priv1, pub2, priv2);

                    println!("Connected as {}", user.get_username());

                    // Menu if user is connected
                    loop {
                        let select = Select::new("What do you want to do?",
                                                 vec!["send message", "receive messages","change password", "logout"])
                            .prompt()?;

                        match select {
                            "send message" => {
                                send_message::send_message(&mut srv, &user)?;
                            }
                            "receive messages" => {
                                receive_message::receive_message(&mut srv, &user)?;
                            }
                            "change password" => {
                                login::change_password(&mut srv, &user)?;

                                println!("Logged out successfully");
                                break;
                            }
                            "logout" => {
                                println!("Logged out successfully");
                                break;
                            }
                            _ => unreachable!(),
                        }
                    }

                } else {
                    println!("Operation successful");
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}
