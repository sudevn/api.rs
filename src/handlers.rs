use actix_web::{web, HttpRequest, HttpResponse};
use rand::Rng;
use serde_json::json;

use crate::auth::{verify_admin_token, verify_api_key, verify_password, AdminTokens};
use crate::db::DB;
use crate::models::*;

pub async fn admin_login(
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

pub async fn admin_logout(req: HttpRequest, admin_tokens: web::Data<AdminTokens>) -> HttpResponse {
    if let Some(token) = req.headers().get("X-Admin-Token") {
        if let Ok(token_str) = token.to_str() {
            admin_tokens.lock().unwrap().remove(token_str);
            return HttpResponse::Ok().json(json!({"message": "Logged out successfully"}));
        }
    }
    HttpResponse::Unauthorized().json(json!({"error": "Invalid token"}))
}

pub async fn greet(
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

pub async fn create_api_key(
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

pub async fn delete_api_key(
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
