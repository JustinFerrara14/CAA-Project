use std::time::{SystemTime, Instant};
use libsodium_sys::*;
use lhtlp::LHTLP;
use num_bigint::BigUint;

use crate::database::{Database, Message};
use crate::consts::*;
use rand::rngs::OsRng;
use rand::RngCore;
use opaque_ke::*;
use opaque_ke::ksf::Ksf;
use std::default::Default;
use argon2::Argon2;

#[allow(dead_code)]
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = Argon2<'static>;
}


pub struct Server {
    pub(crate) db: Database,
    server_opaque: ServerSetup<DefaultCipherSuite>,
}

impl Server {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);

        Server {
            db: Database::new(),
            server_opaque: server_setup,
        }
    }

    pub fn server_registration_start(&mut self, username: &str,client_registration_start_result: ClientRegistrationStartResult<DefaultCipherSuite>) -> Result<ServerRegistrationStartResult<DefaultCipherSuite>, Box<dyn std::error::Error>> {
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &self.server_opaque,
            client_registration_start_result.message,
            username.as_bytes(),
        ).map_err(|e| e.to_string())?;

        Ok(server_registration_start_result)
    }

    pub fn server_registration_finish(&mut self, client_registration_finish_result: ClientRegistrationFinishResult<DefaultCipherSuite>,
        username: String,
        cpriv1: Vec<u8>,
        nonce1: [u8; SYM_LEN_NONCE],
        pub1: [u8; ENC_KEY_LEN_PUB],
        cpriv2: Vec<u8>,
        nonce2: [u8; SYM_LEN_NONCE],
        pub2: [u8; SIGN_KEY_LEN_PUB]
    ) -> Result<(), Box<dyn std::error::Error>> {
        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(
            client_registration_finish_result.message,
        );

        let password_file_bytes = password_file.serialize();

        if self.db.get_user(&username).is_some() {
            // TODO check if the user is connected
            self.db.modify_user(
                username, password_file_bytes, cpriv1, nonce1, pub1, cpriv2, nonce2, pub2,
            )?;
        } else {
            self.db.create_user(
                username,
                password_file_bytes,
                cpriv1,
                nonce1,
                pub1,
                cpriv2,
                nonce2,
                pub2,
            )?;
        }

        Ok(())
    }

    pub fn server_login_start(&mut self, username: &str, client_login_start_result: ClientLoginStartResult<DefaultCipherSuite>) -> Result<ServerLoginStartResult<DefaultCipherSuite>, Box<dyn std::error::Error>> {
        let password_file_bytes = self.db.get_user(&username).ok_or("User not found")?.password_file.clone();

        let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes).map_err(|e| e.to_string())?;

        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &self.server_opaque,
            Some(password_file),
            client_login_start_result.message,
            username.as_bytes(),
            ServerLoginStartParameters::default(),
        ).map_err(|e| e.to_string())?;

        Ok(server_login_start_result)
    }

    pub fn server_login_finish(&mut self, username: &str, server_login_start_result: ServerLoginStartResult<DefaultCipherSuite>, client_login_finish_result: ClientLoginFinishResult<DefaultCipherSuite>) -> Result<([u8; ENC_KEY_LEN_PUB], Vec<u8>, [u8; SYM_LEN_NONCE], [u8; SIGN_KEY_LEN_PUB], Vec<u8>, [u8; SYM_LEN_NONCE]), Box<dyn std::error::Error>> {

        let server_login_finish_result = server_login_start_result.state.finish(
            client_login_finish_result.message,
        ).map_err(|e| e.to_string())?;

        // TODO use to communicate with the client
        let key = server_login_finish_result.session_key.clone();

        let user = self.db.get_user(&*username).unwrap();

        Ok((
            user.asysm_key_encryption.public_key.clone(),
            user.asysm_key_encryption.cipher_private_key.clone(),
            user.asysm_key_encryption.nonce.clone(),
            user.asysm_key_signing.public_key.clone(),
            user.asysm_key_signing.cipher_private_key.clone(),
            user.asysm_key_signing.nonce.clone(),
        ))
    }

    pub fn get_pub_key1(& self, username: &str) -> Option<[u8; ENC_KEY_LEN_PUB]> {
        self.db.get_user(username).map(|u| u.asysm_key_encryption.public_key.clone())
    }

    pub fn get_pub_key2(& self, username: &str) -> Option<[u8; SIGN_KEY_LEN_PUB]> {
        self.db.get_user(username).map(|u| u.asysm_key_signing.public_key.clone())
    }

    pub fn send_message(&mut self, /*hash: String,*/ sender: &str, receiver: &str, delivery_time: SystemTime, filename: Vec<u8>, nonce_filename: [u8; ENC_LEN_NONCE], message: Vec<u8>, nonce_message: [u8; ENC_LEN_NONCE], signature: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {

        // Check if the user is connected using login function
        // if self.login(sender, &hash).is_err() {
        //     println!("User not connected");
        //     return Err("User not connected".into());
        // }

        // TODO: decrypt the content of the message using session_key

        self.db.send_message(sender, receiver, delivery_time, filename, nonce_filename, message, nonce_message, signature)?;

        Ok(())
    }

    pub fn get_messages(&mut self, /*hash: String,*/ username: &str) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
        // Check if the user is connected
        // if self.login(username, &hash).is_err() {
        //     println!("User not connected");
        //     return Err("User not connected".into());
        // }

        // TODO: decrypt the content of the request using session_key of the user

        let messages = self.db.get_messages(username)?;

        let now = SystemTime::now();

        // Make a copy of the messages
        let mut copied_messages: Vec<Message> = messages.iter().cloned().collect();

        // Remove the nonce_message if the delivery_time is in the future
        for m in &mut copied_messages {

            if m.delivery_time > now {

                // Generate time puzzles

                // time in seconds
                let time = m.delivery_time.duration_since(now).unwrap().as_secs();

                let complexity = time * TIME_HARDNESS / 3;

                let lhtlp = LHTLP::setup(LAMBDA, BigUint::from(complexity));


                let secret = u64::from_le_bytes(m.nonce_message[..8].try_into().unwrap()); // Premier bloc
                let secret2 = u64::from_le_bytes(m.nonce_message[8..16].try_into().unwrap()); // Deuxième bloc
                let secret3 = u64::from_le_bytes(m.nonce_message[16..].try_into().unwrap()); // Troisième bloc

                // Générer des puzzles pour chaque bloc
                let puzzle1 = lhtlp.generate(secret);
                let puzzle2 = lhtlp.generate(secret2);
                let puzzle3 = lhtlp.generate(secret3);


                // check the time needed
                // println!("Time needed to take in seconds: {:?}", time);
                //
                // let start_time = Instant::now();
                // let solution = lhtlp.solve(puzzle1.clone());
                // let solution = lhtlp.solve(puzzle1.clone());
                // let solution = lhtlp.solve(puzzle1.clone());
                // let duration = start_time.elapsed();
                //
                // println!("Time needed to solve the puzzle: {:?}", duration);

                m.puzzle_struct = lhtlp;
                m.nonce_message = [0u8; ENC_LEN_NONCE];
                m.puzzles = vec![puzzle1, puzzle2, puzzle3];
            }
        }

        Ok(copied_messages)
    }
}
