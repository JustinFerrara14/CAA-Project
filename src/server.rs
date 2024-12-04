
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
}