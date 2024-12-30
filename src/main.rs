mod consts;
mod database;
mod login;
mod receive_message;
mod send_message;
mod server;
mod user_connected;

use crate::server::Server;
use inquire::{Select};
use libsodium_sys::*;
use user_connected::UserConnected;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize libsodium
    if unsafe { sodium_init() } == -1 {
        panic!("libsodium init failed");
    }

    let mut srv = server::Server::new();

    loop {
        let select =
            Select::new("What do you want to do?", vec!["login", "register", "exit"]).prompt()?;

        match select {
            "login" => {
                let result = login::login(&mut srv);

                match result {
                    Ok((username, key, key_communication, mac, pub1, priv1, pub2, priv2)) => {
                        let user = UserConnected::new(
                            username,
                            key,
                            key_communication,
                            mac,
                            pub1,
                            priv1,
                            pub2,
                            priv2,
                        );

                        println!("Operation successful");
                        println!("Connected as {}", user.get_username());

                        // Menu if user is connected
                        loop {
                            let select = Select::new(
                                "What do you want to do?",
                                vec![
                                    "send message",
                                    "receive messages",
                                    "change password",
                                    "logout",
                                ],
                            )
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
                                    login::logout(&mut srv, &user)?;

                                    println!("Logged out successfully");
                                    break;
                                }
                                "logout" => {
                                    login::logout(&mut srv, &user)?;

                                    println!("Logged out successfully");
                                    break;
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    Err(_) => {
                        println!("Error: login");
                    }
                }
            }

            "register" => {
                let result = login::register(&mut srv).map_err(|_| "Error: registering");

                match result {
                    Ok(_) => {
                        println!("Operation successful");
                    }
                    Err(_) => {
                        println!("Error: registering");
                    }
                }
            }
            "exit" => return Ok(()),
            _ => unreachable!(),
        }
    }
}
