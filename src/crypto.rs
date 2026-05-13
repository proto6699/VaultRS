use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng as ChaChaOsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::errors::AppError;

// ── password hashing (for login verification) ──────────────────────────────

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AppError::Crypto)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(hash).map_err(|_| AppError::Crypto)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

// ── key derivation (turns master password into encryption key) ─────────────

pub fn derive_key(password: &str, salt_hex: &str) -> Result<Vec<u8>, AppError> {
    let salt_bytes = hex::decode(salt_hex).map_err(|_| AppError::Crypto)?;
    let mut key = vec![0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key)
        .map_err(|_| AppError::Crypto)?;
    Ok(key)
}

pub fn generate_kdf_salt() -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    hex::encode(salt)
}

// ── encryption / decryption ────────────────────────────────────────────────

pub fn encrypt(plaintext: &str, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| AppError::Crypto)?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| AppError::Crypto)?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8]) -> Result<String, AppError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| AppError::Crypto)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::Crypto)?;

    let result = String::from_utf8(plaintext.clone()).map_err(|_| AppError::Crypto)?;
    plaintext.zeroize();
    Ok(result)
}
