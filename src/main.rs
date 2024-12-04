use inquire::{Text, Select};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let mut server = Server::new();

    loop {
        let select = Select::new("What do you want to do?",
                                 vec!["register", "authenticate", "exit"])
            .prompt()?;

        let result = match select {
            "register" => todo!(), //register(&mut db),
            "authenticate" => todo!(), //authenticate(&mut db),
            "exit" => return Ok(()),
            _ => unreachable!(),
        };

    }
}
