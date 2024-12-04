use crate::database::Database;

pub struct Server {
    pub(crate) db: Database,
}

impl Server {
    pub fn new() -> Self {
        Server {
            db: Database::new(),
        }
    }

    pub fn register(
        &mut self,
        username: String,
        salt: String,
        hash: String,
        cpriv1: String,
        pub1: String,
        cpriv2: String,
        pub2: String,
    ) -> Result<(), Box<dyn std::error::Error>> {

        if self.db.get_user(&username).is_some() {
            println!("User already exists");
            return Err("User already exists".into());
        }

        self.db.create_user(username, salt, hash, cpriv1, pub1, cpriv2, pub2)?;
        Ok(())
    }

}
