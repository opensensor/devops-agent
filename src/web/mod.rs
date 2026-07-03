pub mod api;

use axum::Router;
use std::future::Future;
use std::path::PathBuf;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

pub async fn create_app(state: api::AppState, static_dir: PathBuf) -> Router {
    let api_router = api::create_router(state);

    // Serve static assets (index.html, styles.css, app.js, ...). Any path that
    // doesn't map to a file falls back to index.html so client-side SPA routes
    // still load. `/api/*` is matched first and never reaches this service.
    let index_path = static_dir.join("index.html");
    let static_service = ServeDir::new(static_dir).not_found_service(ServeFile::new(index_path));

    Router::new()
        .nest("/api", api_router)
        .fallback_service(static_service)
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB request body limit
}

pub async fn start_server_with_shutdown<S>(
    host: String,
    port: u16,
    state: api::AppState,
    static_dir: PathBuf,
    shutdown_signal: S,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: Future<Output = ()> + Send + 'static,
{
    let app = create_app(state, static_dir).await;

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}
