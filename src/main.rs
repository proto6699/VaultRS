use axum::{
    Router,
    routing::{get, post},
};
use tower_http::services::ServeDir;
use tower_sessions::{SessionManagerLayer, cookie::SameSite};
use tower_sessions_sqlx_store::SqliteStore;
use sqlx::SqlitePool;
use std::sync::Arc;
use minijinja::Environment;
use minijinja_autoreload::AutoReloader;

mod auth;
mod vault;
mod crypto;
mod db;
mod models;
mod errors;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub tmpl: Arc<AutoReloader>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let pool = db::create_pool().await;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("failed to run migrations");

    // session store
    let session_store = SqliteStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .expect("failed to create session table");

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax);

    // template engine
    let reloader = AutoReloader::new(|notifier| {
        let mut env = Environment::new();
        let tmpl_path = "templates";
        notifier.watch_path(tmpl_path, true);
        env.set_loader(minijinja::path_loader(tmpl_path));
        Ok(env)
    });

    let state = AppState {
        db: pool,
        tmpl: Arc::new(reloader),
    };

    let app = Router::new()
        .route("/",                     get(auth::login_page))
        .route("/login",                get(auth::login_page).post(auth::login))
        .route("/register",             get(auth::register_page).post(auth::register))
        .route("/logout",               post(auth::logout))
        .route("/vault",                get(vault::vault_page))
        .route("/vault/add",            post(vault::add_entry))
        .route("/vault/delete/:id",     post(vault::delete_entry))
        .route("/vault/search",         get(vault::search_entries))
        .route("/vault/reveal/:id",     get(vault::reveal_entry))
        .nest_service("/static",        ServeDir::new("static"))
        .layer(session_layer)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    tracing::info!("FoxVault running at http://localhost:3000 🦊");
    axum::serve(listener, app).await.unwrap();
}
