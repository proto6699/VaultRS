use axum::{
    extract::State,
    response::{Html, Redirect},
    Form,
};
use tower_sessions::Session;
use uuid::Uuid;
use crate::{
    AppState,
    crypto::{hash_password, verify_password, generate_kdf_salt},
    errors::AppError,
    models::AuthForm,
};

pub const SESSION_USER_ID:  &str = "user_id";
pub const SESSION_USERNAME: &str = "username";
pub const SESSION_KDF_SALT: &str = "kdf_salt";

// ── GET /login ─────────────────────────────────────────────────────────────

pub async fn login_page(
    State(state): State<AppState>,
) -> Result<Html<String>, AppError> {
    let env = state.tmpl.acquire_env()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let tmpl = env.get_template("login.html")
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let html = tmpl.render(minijinja::context! {})
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Html(html))
}

// ── GET /register ──────────────────────────────────────────────────────────

pub async fn register_page(
    State(state): State<AppState>,
) -> Result<Html<String>, AppError> {
    let env = state.tmpl.acquire_env()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let tmpl = env.get_template("register.html")
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let html = tmpl.render(minijinja::context! {})
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Html(html))
}

// ── POST /register ─────────────────────────────────────────────────────────

pub async fn register(
    State(state): State<AppState>,
    Form(form): Form<AuthForm>,
) -> Result<Redirect, AppError> {
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE username = ?"
    )
    .bind(&form.username)
    .fetch_one(&state.db)
    .await?;

    if existing > 0 {
        return Err(AppError::Auth("username already taken".into()));
    }

    let id            = Uuid::new_v4().to_string();
    let password_hash = hash_password(&form.password)?;
    let kdf_salt      = generate_kdf_salt();
    let created_at    = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, kdf_salt, created_at)
         VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&form.username)
    .bind(&password_hash)
    .bind(&kdf_salt)
    .bind(&created_at)
    .execute(&state.db)
    .await?;

    Ok(Redirect::to("/login"))
}

// ── POST /login ────────────────────────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<AuthForm>,
) -> Result<Redirect, AppError> {
    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT id, username, password_hash, kdf_salt, created_at
         FROM users WHERE username = ?"
    )
    .bind(&form.username)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Auth("invalid username or password".into()))?;

    if !verify_password(&form.password, &user.password_hash)? {
        return Err(AppError::Auth("invalid username or password".into()));
    }

    // store everything we need in the session
    session.insert(SESSION_USER_ID,  &user.id).await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    session.insert(SESSION_USERNAME, &user.username).await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    session.insert(SESSION_KDF_SALT, &user.kdf_salt).await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // store master password in session so vault can derive encryption key
    session.insert("master_pw", &form.password).await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Redirect::to("/vault"))
}

// ── POST /logout ───────────────────────────────────────────────────────────

pub async fn logout(
    State(_state): State<AppState>,
    session: Session,
) -> Result<Redirect, AppError> {
    session.flush().await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Redirect::to("/login"))
}
