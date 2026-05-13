CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    kdf_salt      TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
