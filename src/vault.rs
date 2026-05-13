use axum::{
    extract::{Path, Query, State},
    response::{Html, Redirect},
    Form,
};
use std::collections::HashMap;
use tower_sessions::Session;
use crate::{
    AppState,
    auth::{SESSION_USER_ID, SESSION_USERNAME, SESSION_KDF_SALT},
    crypto::{encrypt, decrypt, derive_key},
    errors::AppError,
    models::{NewEntryForm, EntryView, VaultEntry},
};
use uuid::Uuid;

// helper — grabs user info from session or redirects to login
async fn require_auth(session: &Session) -> Result<(String, String, String), Redirect> {
    let user_id  = session.get::<String>(SESSION_USER_ID).await.ok().flatten();
    let username = session.get::<String>(SESSION_USERNAME).await.ok().flatten();
    let kdf_salt = session.get::<String>(SESSION_KDF_SALT).await.ok().flatten();
    match (user_id, username, kdf_salt) {
        (Some(id), Some(u), Some(s)) => Ok((id, u, s)),
        _ => Err(Redirect::to("/login")),
    }
}

// ── GET /vault ─────────────────────────────────────────────────────────────

pub async fn vault_page(
    State(state): State<AppState>,
    session: Session,
) -> Result<Html<String>, Redirect> {
    let (user_id, username, kdf_salt) = require_auth(&session).await?;

    // we need the master password to decrypt — store it temporarily in session
    // For now show entries without decrypting passwords (reveal on demand)
    let rows = sqlx::query_as::<_, VaultEntry>(
        "SELECT id, user_id, site, username, ciphertext, nonce, created_at
         FROM vault_entries WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(&user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let entries: Vec<EntryView> = rows.iter().map(|e| EntryView {
        id:       e.id.clone(),
        site:     e.site.clone(),
        username: e.username.clone(),
        password: String::new(), // hidden until revealed
    }).collect();

    let env = state.tmpl.acquire_env().map_err(|_| Redirect::to("/login"))?;
    let tmpl = env.get_template("vault.html").map_err(|_| Redirect::to("/login"))?;
    let html = tmpl.render(minijinja::context! {
        username    => username,
        entries     => entries,
        entry_count => entries.len(),
    }).map_err(|_| Redirect::to("/login"))?;

    Ok(Html(html))
}

// ── POST /vault/add ────────────────────────────────────────────────────────

pub async fn add_entry(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<NewEntryForm>,
) -> Result<Redirect, AppError> {
    let (user_id, _username, kdf_salt) = require_auth(&session).await
        .map_err(|_| AppError::Auth("not logged in".into()))?;

    // get master password from session
    let master_pw = session.get::<String>("master_pw").await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Auth("session expired, please log in again".into()))?;

    let key = derive_key(&master_pw, &kdf_salt)?;
    let (ciphertext, nonce) = encrypt(&form.password, &key)?;

    let id         = Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO vault_entries (id, user_id, site, username, ciphertext, nonce, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&user_id)
    .bind(&form.site)
    .bind(&form.username)
    .bind(&ciphertext)
    .bind(&nonce)
    .bind(&created_at)
    .execute(&state.db)
    .await?;

    Ok(Redirect::to("/vault"))
}

// ── POST /vault/delete/:id ─────────────────────────────────────────────────

pub async fn delete_entry(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> Result<Redirect, AppError> {
    let (user_id, _, _) = require_auth(&session).await
        .map_err(|_| AppError::Auth("not logged in".into()))?;

    sqlx::query("DELETE FROM vault_entries WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    Ok(Redirect::to("/vault"))
}

// ── GET /vault/search ──────────────────────────────────────────────────────
pub async fn search_entries(
    State(state): State<AppState>,
    session: Session,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Html<String>, AppError> {
    let (user_id, _, _) = require_auth(&session).await
        .map_err(|_| AppError::Auth("not logged in".into()))?;

    let q = params.get("q").cloned().unwrap_or_default();
    let pattern = format!("%{}%", q);

    let rows = sqlx::query_as::<_, VaultEntry>(
        "SELECT id, user_id, site, username, ciphertext, nonce, created_at
         FROM vault_entries WHERE user_id = ? AND (site LIKE ? OR username LIKE ?)
         ORDER BY created_at DESC"
    )
    .bind(&user_id)
    .bind(&pattern)
    .bind(&pattern)
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        return Ok(Html(
            "<div class=\"text-center py-16 font-mono text-stone text-sm\">\
              <div class=\"text-4xl mb-4\">🦊</div>\
              <div>no entries found...</div>\
             </div>".to_string()
        ));
    }

    let mut html = String::new();
    for e in &rows {
        let initials = e.site.chars().take(2).collect::<String>().to_uppercase();
        html.push_str("<div class=\"bg-cream gold-border rounded-lg px-5 py-4 flex items-center gap-4\">");
        html.push_str("<div class=\"w-9 h-9 rounded bg-ink2 border border-stone flex items-center justify-center font-cinzel font-bold text-goldlt text-xs shrink-0\">");
        html.push_str(&initials);
        html.push_str("</div>");
        html.push_str("<div class=\"flex-1 min-w-0\">");
        html.push_str("<div class=\"font-cinzel font-bold text-ink text-sm tracking-wide\">");
        html.push_str(&e.site);
        html.push_str("</div>");
        html.push_str("<div class=\"font-mono text-xs text-stone mt-0.5\">");
        html.push_str(&e.username);
        html.push_str("</div>");
        html.push_str("</div>");
        html.push_str("<div class=\"flex gap-2 shrink-0\">");
        html.push_str("<form method=\"POST\" action=\"/vault/delete/");
        html.push_str(&e.id);
        html.push_str("\"><button class=\"font-mono text-xs text-red border border-red/20 px-3 py-1 rounded\">delete</button></form>");
        html.push_str("</div>");
        html.push_str("</div>");
    }

    Ok(Html(html))
}

// ── GET /vault/reveal/:id ──────────────────────────────────────────────────

pub async fn reveal_entry(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> Result<Html<String>, AppError> {
    let (user_id, _, kdf_salt) = require_auth(&session).await
        .map_err(|_| AppError::Auth("not logged in".into()))?;

    let master_pw = session.get::<String>("master_pw").await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Auth("session expired".into()))?;

    let entry = sqlx::query_as::<_, VaultEntry>(
        "SELECT id, user_id, site, username, ciphertext, nonce, created_at
         FROM vault_entries WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let key = derive_key(&master_pw, &kdf_salt)?;
    let plaintext = decrypt(&entry.ciphertext, &entry.nonce, &key)?;

    Ok(Html(plaintext))
}