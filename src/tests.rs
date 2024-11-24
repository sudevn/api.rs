use crate::models::*;
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
