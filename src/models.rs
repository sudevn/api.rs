use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Serialize, Debug, Deserialize)]
pub struct NameRequest {
    pub name: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct GreetingResponse {
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKey {
    pub id: Thing,
    pub key: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct AdminCredentials {
    pub username: String,
    pub password_hash: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct AdminLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct AdminLoginResponse {
    pub token: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub key: String,
}
