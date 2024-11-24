use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use surrealdb::{engine::remote::ws::Client, Result as SurrealResult, Surreal};

use crate::models::ApiKey;

pub type AdminTokens = Arc<Mutex<HashSet<String>>>;

pub async fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub async fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub async fn verify_api_key(db: &Surreal<Client>, api_key: &str) -> SurrealResult<bool> {
    println!("Verifying API key: {:?}", api_key);
    let mut result = db
        .query("SELECT * FROM apikeys WHERE key = $key")
        .bind(("key", api_key.to_string()))
        .await?;

    let exists: Vec<ApiKey> = result.take(0)?;
    for api_key in &exists {
        println!("Found API key: {}", api_key.key);
    }
    Ok(!exists.is_empty())
}

pub fn verify_admin_token(token: &str, admin_tokens: &AdminTokens) -> bool {
    admin_tokens.lock().unwrap().contains(token)
}
