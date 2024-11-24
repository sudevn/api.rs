use std::sync::Arc;
use surrealdb::{
    engine::remote::ws::{Client, Ws},
    Surreal,
};

use crate::auth::hash_password;
use crate::models::AdminCredentials;

pub type DB = Arc<Surreal<Client>>;

pub async fn init_admin_credentials(db: &Surreal<Client>) -> surrealdb::Result<()> {
    let mut result = db
        .query("SELECT * FROM admin WHERE username = $username")
        .bind(("username", "admin"))
        .await?;

    let exists: Vec<AdminCredentials> = result.take(0)?;
    if exists.is_empty() {
        let password_hash = hash_password("admin123")
            .await
            .map_err(|e| (format!("Failed to hash password: {}", e)));

        db.query("CREATE admin SET username = $username, password_hash = $password_hash")
            .bind(("username", "admin"))
            .bind(("password_hash", password_hash.unwrap()))
            .await?;
    }

    Ok(())
}

pub async fn setup_database() -> DB {
    println!("Connecting to database...");

    let mut retry_count = 0;
    let max_retries = 3;
    let mut db = None;

    while retry_count < max_retries {
        match Surreal::new::<Ws>("127.0.0.1:8000").await {
            Ok(connection) => {
                db = Some(connection);
                break;
            }
            Err(e) => {
                println!("Connection attempt {} failed: {:?}", retry_count + 1, e);
                retry_count += 1;
                if retry_count < max_retries {
                    println!("Retrying in 2 seconds...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    let db = db.expect("Failed to connect to database after multiple attempts");

    println!("Connected to database. Signing in...");

    db.signin(surrealdb::opt::auth::Root {
        username: "root",
        password: "root",
    })
    .await
    .expect("Failed to sign in to database");

    println!("Signed in. Selecting namespace and database...");

    db.use_ns("test")
        .use_db("test")
        .await
        .expect("Failed to select namespace and database");

    println!("Initializing database...");

    init_admin_credentials(&db)
        .await
        .expect("Failed to initialize admin credentials");

    println!("Database initialized.");

    Arc::new(db)
}
