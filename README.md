# FoxVault 🦊

> *"your hopefully safe password den"*

A secure, self-hosted password manager built with Rust. Stores your passwords encrypted at rest, themed after a certain sleepy pixel fox.

![Rust](https://img.shields.io/badge/Rust-2021-orange?style=flat&logo=rust)
![SQLite](https://img.shields.io/badge/Database-SQLite-blue?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

---

## what is this

FoxVault is a web-based password manager you run locally on your own machine.

Your passwords never leave your computer. Everything is encrypted with ChaCha20-Poly1305 and your master password is never stored anywhere.

---

## features

- 🔐 register / login with a master password
- 🗄️ add, search, reveal, and delete vault entries
- 🔑 passwords encrypted at rest with ChaCha20-Poly1305
- 🦊 password generator with three modes and unhinged fox lore
- 🎨 earthy fantasy / zelda-inspired UI with a sleepy pixel fox

---

## tech stack

| thing | what |
|---|---|
| backend | Rust + Axum |
| database | SQLite + SQLx |
| auth | tower-sessions |
| crypto | Argon2id + ChaCha20-Poly1305 |
| frontend | HTMX + Tailwind CSS |
| templates | MiniJinja |

---

## running it yourself

### requirements

- Rust → https://rustup.rs
- sqlx-cli

Install sqlx-cli:

```bash
cargo install sqlx-cli --no-default-features --features sqlite
```

---

## setup

### 1. clone the repo

```bash
git clone https://github.com/proto6699/vaultrs.git
cd vaultrs
```

---

### 2. create a `.env` file

Create a file named `.env` in the project root:

```env
DATABASE_URL=sqlite:/full/path/to/vaultrs/vault.db
SESSION_SECRET=make-this-a-long-random-string-at-least-64-chars
```

Generate a secure session secret:

```bash
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 64
```

---

### 3. create the database

```bash
export DATABASE_URL=sqlite:/full/path/to/vaultrs/vault.db

sqlx database create
sqlx migrate run
```

---

### 4. run the app

```bash
cargo run
```

---

### 5. open in browser

```txt
http://localhost:3000
```

---

## project structure

```txt
src/
├── main.rs       # axum router + app setup
├── auth.rs       # register, login, logout
├── vault.rs      # vault CRUD handlers
├── crypto.rs     # argon2 + chacha20 logic
├── db.rs         # sqlite pool
├── models.rs     # data structs
└── errors.rs     # error handling

templates/        # MiniJinja HTML templates
migrations/       # SQLite schema
static/           # images, css
```

---

## security notes

- master password is never stored
- only an Argon2id hash is saved for verification
- encryption key is derived fresh from your password on login
- encryption key lives only in session memory
- each vault entry uses a unique random nonce
- sensitive password buffers are zeroized after use
- `.env` and `vault.db` are gitignored

---

## credits

built by a gremlin, themed after a sleepy pixel fox 🦊
