use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::fs;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/*path", get(file_handler))
        .route("/", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> Response {
    let p = std::path::Path::new(&state.path).join(path);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} note found", p.display()),
        )
            .into_response()
    } else if p.is_dir() {
        info!("Reading directory {:?}", p);
        let mut read_dir = fs::read_dir(p.clone()).await.unwrap();

        let mut subdirs = vec!["..".to_string()];
        while let Some(entry) = read_dir.next_entry().await.unwrap() {
            let v = entry.file_name().into_string().unwrap();
            subdirs.push(v);
        }
        let items = subdirs
            .into_iter()
            .map(|item| {
                format!(
                    "<li><a href=\"/{}/{}\">{}</a></li>",
                    p.to_string_lossy(),
                    item,
                    item
                )
            })
            .collect::<Vec<String>>()
            .join("");

        let content = format!("<html><body><ul>{}</ul></body></html>", items);
        Html(content).into_response()
    } else {
        info!("Reading file {:?}", p);

        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, content).into_response()
            }
            Err(e) => {
                warn!("Error reading file: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let response = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
