use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub kdf_salt: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VaultEntry {
    pub id: String,
    pub user_id: String,
    pub site: String,
    pub username: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct NewEntryForm {
    pub site: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct EntryView {
    pub id: String,
    pub site: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthForm {
    pub username: String,
    pub password: String,
}