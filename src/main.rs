use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use surrealdb::engine::remote::ws::{Client, Ws};
use surrealdb::{sql::Thing, Result as SurrealResult, Surreal};

// Structures for API
#[derive(Serialize, Debug, Deserialize)]
struct NameRequest {
    name: String,
}

#[derive(Serialize, Debug, Deserialize)]
struct GreetingResponse {
    message: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ApiKey {
    id: Thing,
    key: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Debug, Deserialize)]
struct AdminCredentials {
    username: String,
    password_hash: String,
}

#[derive(Serialize, Debug, Deserialize)]
struct AdminLoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize, Debug, Deserialize)]
struct AdminLoginResponse {
    token: String,
}

#[derive(Serialize, Debug, Deserialize)]
struct CreateApiKeyRequest {
    key: String,
}

#[derive(Debug, Serialize)]
struct ApiKeyResponse {
    key: String,
}

// Application state
type DB = Arc<Surreal<Client>>;
type AdminTokens = Arc<Mutex<HashSet<String>>>;

// Helper functions
async fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

async fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

// Authentication functions
async fn verify_api_key(db: &Surreal<Client>, api_key: &str) -> SurrealResult<bool> {
    println!("Verifying API key: {:?}", api_key);
    let mut result = db
        .query("SELECT * FROM apikeys WHERE key = $key")
        .bind(("key", api_key.to_string())) // Convert to owned String
        .await?;

    let exists: Vec<ApiKey> = result.take(0)?;
    for api_key in &exists {
        println!("Found API key: {}", api_key.key);
    }
    Ok(!exists.is_empty())
}

fn verify_admin_token(token: &str, admin_tokens: &AdminTokens) -> bool {
    admin_tokens.lock().unwrap().contains(token)
}

// Route handlers
async fn admin_login(
    login_req: web::Json<AdminLoginRequest>,
    db: web::Data<DB>,
    admin_tokens: web::Data<AdminTokens>,
) -> HttpResponse {
    let result = db
        .query("SELECT * FROM admin WHERE username = $username")
        .bind(("username", login_req.username.clone()))
        .await;

    let admin_creds: Vec<AdminCredentials> = match result {
        Ok(mut response) => match response.take(0) {
            Ok(creds) => creds,
            Err(_) => {
                return HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"}))
            }
        },
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({"error": "Database error"}))
        }
    };

    if admin_creds.is_empty() {
        return HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"}));
    }

    let admin = &admin_creds[0];
    if !verify_password(&login_req.password, &admin.password_hash).await {
        return HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"}));
    }

    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    admin_tokens.lock().unwrap().insert(token.clone());

    HttpResponse::Ok().json(AdminLoginResponse { token })
}

async fn admin_logout(req: HttpRequest, admin_tokens: web::Data<AdminTokens>) -> HttpResponse {
    if let Some(token) = req.headers().get("X-Admin-Token") {
        if let Ok(token_str) = token.to_str() {
            admin_tokens.lock().unwrap().remove(token_str);
            return HttpResponse::Ok().json(json!({"message": "Logged out successfully"}));
        }
    }
    HttpResponse::Unauthorized().json(json!({"error": "Invalid token"}))
}

async fn greet(
    req: HttpRequest,
    name_req: web::Json<NameRequest>,
    db: web::Data<DB>,
) -> HttpResponse {
    let api_key = match req.headers().get("X-API-Key") {
        Some(key) => match key.to_str() {
            Ok(k) => k,
            Err(_) => {
                return HttpResponse::Unauthorized()
                    .json(json!({"error": "Invalid API key format"}))
            }
        },
        None => return HttpResponse::Unauthorized().json(json!({"error": "API key missing"})),
    };

    match verify_api_key(&db, api_key).await {
        Ok(true) => {
            let response = GreetingResponse {
                message: format!("hi {}", name_req.name),
            };
            HttpResponse::Ok().json(response)
        }
        Ok(false) => HttpResponse::Unauthorized().json(json!({"error": "Invalid API key"})),
        Err(e) => {
            println!("Database error: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"error": "Database error"}))
        }
    }
}

async fn create_api_key(
    req: HttpRequest,
    key_req: web::Json<CreateApiKeyRequest>,
    db: web::Data<DB>,
    admin_tokens: web::Data<AdminTokens>,
) -> HttpResponse {
    let token = match req.headers().get("X-Admin-Token") {
        Some(t) => match t.to_str() {
            Ok(t) => t,
            Err(_) => {
                return HttpResponse::Unauthorized().json(json!({"error": "Invalid token format"}))
            }
        },
        None => return HttpResponse::Unauthorized().json(json!({"error": "Admin token missing"})),
    };

    if !verify_admin_token(token, &admin_tokens) {
        return HttpResponse::Unauthorized().json(json!({"error": "Invalid admin token"}));
    }

    let key_str = key_req.key.clone();

    let create_result = db
        .query("CREATE type::thing('apikeys', $key) SET key = $key, created_at = $created_at")
        .bind(("key", key_str.to_string()))
        .bind(("created_at", chrono::Utc::now()))
        .await;

    match create_result {
        Ok(_) => HttpResponse::Ok().json(ApiKeyResponse { key: key_str }),
        Err(e) => {
            println!("Error creating API key: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"error": "Failed to create API key"}))
        }
    }
}

async fn delete_api_key(
    req: HttpRequest,
    key_req: web::Json<CreateApiKeyRequest>,
    db: web::Data<DB>,
    admin_tokens: web::Data<AdminTokens>,
) -> HttpResponse {
    let token = match req.headers().get("X-Admin-Token") {
        Some(t) => match t.to_str() {
            Ok(t) => t,
            Err(_) => {
                return HttpResponse::Unauthorized().json(json!({"error": "Invalid token format"}))
            }
        },
        None => return HttpResponse::Unauthorized().json(json!({"error": "Admin token missing"})),
    };

    if !verify_admin_token(token, &admin_tokens) {
        return HttpResponse::Unauthorized().json(json!({"error": "Invalid admin token"}));
    }

    let key_str = key_req.key.clone();

    match db
        .query("DELETE FROM apikeys WHERE key = $key")
        .bind(("key", key_str.to_string()))
        .await
    {
        Ok(_) => HttpResponse::Ok().json(json!({"message": "API key deleted"})),
        Err(e) => {
            println!("Error deleting API key: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"error": "Failed to delete API key"}))
        }
    }
}

async fn init_admin_credentials(db: &Surreal<Client>) -> SurrealResult<()> {
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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

    let db = Arc::new(db);
    let admin_tokens: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    println!("Server starting at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(admin_tokens.clone()))
            .route("/greet", web::post().to(greet))
            .route("/admin/login", web::post().to(admin_login))
            .route("/admin/logout", web::post().to(admin_logout))
            .route("/api-keys", web::post().to(create_api_key))
            .route("/api-keys", web::delete().to(delete_api_key))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;
    use std::time::Duration;

    const API_URL: &str = "http://127.0.0.1:8080";

    async fn wait_for_server() {
        let client = reqwest::Client::new();
        let mut attempts = 0;
        while attempts < 5 {
            if client
                .post(format!("{}/greet", API_URL))
                .timeout(Duration::from_secs(1))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            attempts += 1;
        }
        panic!("Server did not start in time");
    }

    async fn get_admin_token() -> String {
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/admin/login", API_URL))
            .json(&AdminLoginRequest {
                username: "admin".to_string(),
                password: "admin123".to_string(),
            })
            .send()
            .await
            .expect("Failed to login");

        let login_response: AdminLoginResponse = response
            .json()
            .await
            .expect("Failed to parse login response");
        login_response.token
    }

    #[tokio::test]
    async fn test_admin_login() {
        wait_for_server().await;

        let client = reqwest::Client::new();

        // Test with correct credentials
        let response = client
            .post(format!("{}/admin/login", API_URL))
            .json(&AdminLoginRequest {
                username: "admin".to_string(),
                password: "admin123".to_string(),
            })
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(response.status(), 200);
        let login_response: AdminLoginResponse = response
            .json()
            .await
            .expect("Failed to parse login response");
        assert!(!login_response.token.is_empty());

        // Test with incorrect credentials
        let response = client
            .post(format!("{}/admin/login", API_URL))
            .json(&AdminLoginRequest {
                username: "admin".to_string(),
                password: "wrongpassword".to_string(),
            })
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_api_key_management() {
        wait_for_server().await;

        let client = reqwest::Client::new();
        let admin_token = get_admin_token().await;

        // Create new API key
        let test_key = "test-key-789";
        let mut headers = HeaderMap::new();
        headers.insert("X-Admin-Token", admin_token.parse().unwrap());

        let response = client
            .post(format!("{}/api-keys", API_URL))
            .headers(headers.clone())
            .json(&CreateApiKeyRequest {
                key: test_key.to_string(),
            })
            .send()
            .await
            .expect("Failed to create API key");

        assert_eq!(response.status(), 200);

        // Test the new API key
        let mut api_headers = HeaderMap::new();
        api_headers.insert("X-API-Key", test_key.parse().unwrap());

        let response = client
            .post(format!("{}/greet", API_URL))
            .headers(api_headers)
            .json(&NameRequest {
                name: "test".to_string(),
            })
            .send()
            .await
            .expect("Failed to execute request");

        assert_eq!(response.status(), 200);

        // Delete the API key
        let response = client
            .delete(format!("{}/api-keys", API_URL))
            .headers(headers)
            .json(&CreateApiKeyRequest {
                key: test_key.to_string(),
            })
            .send()
            .await
            .expect("Failed to delete API key");

        assert_eq!(response.status(), 200);
    }
}
