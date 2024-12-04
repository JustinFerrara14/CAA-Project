
use inquire::Text;

pub fn login () -> Result<(), Box<dyn std::error::Error>> {
    let username = Text::new("Enter your username:").prompt()?;
    let password = Text::new("Enter your password:").prompt()?;
    // let mut db = Database::new();
    // db.login(username, password)?;
    Ok(())
}