mod auth;
mod db;
mod handlers;
mod models;
#[cfg(test)]
mod tests;

use actix_web::{web, App, HttpServer};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db = db::setup_database().await;
    let admin_tokens: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    println!("Server starting at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(admin_tokens.clone()))
            .route("/greet", web::post().to(handlers::greet))
            .route("/admin/login", web::post().to(handlers::admin_login))
            .route("/admin/logout", web::post().to(handlers::admin_logout))
            .route("/api-keys", web::post().to(handlers::create_api_key))
            .route("/api-keys", web::delete().to(handlers::delete_api_key))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
