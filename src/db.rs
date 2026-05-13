use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::env;

pub async fn create_pool() -> SqlitePool {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to sqlite database")
}