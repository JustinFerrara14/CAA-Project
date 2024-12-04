mod register;
mod login;
mod database;
mod server;

use inquire::{Text, Select};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut srv = server::Server::new();

    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["login", "register", "exit"])
            .prompt()?;

        let result = match select {
            "login" => login::login(),
            "register" => register::register(&mut srv),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };
    }
}
