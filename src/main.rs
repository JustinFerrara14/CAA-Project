mod register;
mod login;
mod database;
mod server;

use inquire::{Text, Select};
use ecies::{SecretKey, PublicKey};

struct UserConnected {
    connected: bool,
    username: String,
    h: String,
    k: Vec<u8>,
    pub1: PublicKey,
    priv1: SecretKey,
    pub2: PublicKey,
    priv2: SecretKey,
}

// take a UserConnected as argument
fn menu_connected(user: UserConnected) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["send message", "receive messages", "logout"])
            .prompt()?;

        match select {
            "send message" => {
                // TODO
                println!("TODO send message");
            }
            "receive messages" => {
                // TODO
                println!("TODO receive messages");
            }
            "logout" => {
                println!("Logged out successfully");
                return Ok(());
            }
            _ => unreachable!(),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut srv = server::Server::new();

    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["login", "register", "exit"])
            .prompt()?;

        let result = match select {
            "login" => login::login(&mut srv),
            "register" => register::register(&mut srv),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

        match result {
            Ok((connected, username, h, k, pub1, priv1, pub2, priv2)) => {
                if connected {
                    let user = UserConnected {
                        connected,
                        username,
                        h,
                        k,
                        pub1,
                        priv1,
                        pub2,
                        priv2,
                    };

                    println!("Connected as {}", user.username);

                    menu_connected(user)?;

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
