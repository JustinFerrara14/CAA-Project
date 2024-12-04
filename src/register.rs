
use inquire::Text;
use crate::server::Server;
pub fn register(srv: &mut Server) -> Result<(), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    let password_confirm = Text::new("Confirm your password:").prompt()?;

    if password != password_confirm {
        println!("Passwords do not match");
        return Ok(());
    }

    let salt = "salt".to_string();
    let hash = "hash".to_string();
    let cpriv1 = "cpriv1".to_string();
    let pub1 = "pub1".to_string();
    let cpriv2 = "cpriv2".to_string();
    let pub2 = "pub2".to_string();

    srv.db.register(username, salt, hash, cpriv1, pub1, cpriv2, pub2)?;

    Ok(())
}