CREATE TABLE IF NOT EXISTS vault_entries (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site       TEXT NOT NULL,
    username   TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    created_at TEXT NOT NULL
);