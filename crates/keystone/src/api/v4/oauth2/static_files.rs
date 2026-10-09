// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//! Operator-supplied static assets for the OAuth2 pages (`[oauth2]
//! static_dir`): stylesheets and logos referenced from the page templates.

use std::path::{Component, Path, PathBuf};

use axum::{
    extract::{Path as UrlPath, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::keystone::ServiceState;

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("css") => "text/css; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("webp") => "image/webp",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        _ => "application/octet-stream",
    }
}

/// Resolve `requested` below `root`, refusing anything that is not a plain
/// relative path and anything whose canonical location (symlinks included)
/// leaves `root`.
async fn resolve(root: &Path, requested: &str) -> Option<PathBuf> {
    let rel = Path::new(requested);
    if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return None;
    }
    let root = tokio::fs::canonicalize(root).await.ok()?;
    let full = tokio::fs::canonicalize(root.join(rel)).await.ok()?;
    full.starts_with(&root).then_some(full)
}

/// `GET /v4/oauth2/static/{path}`. Serves files from `[oauth2] static_dir`;
/// `404` when it is not configured or the file does not exist.
#[utoipa::path(
    get,
    path = "/static/{*path}",
    operation_id = "/oauth2:static",
    params(("path" = String, Path, description = "Asset path below the static directory")),
    responses(
        (status = OK, description = "Static asset"),
        (status = NOT_FOUND, description = "Not configured or no such file"),
    ),
    tag = "oauth2"
)]
pub(super) async fn static_file(
    State(state): State<ServiceState>,
    UrlPath(path): UrlPath<String>,
) -> Response {
    let dir = state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .static_dir
        .clone();
    let Some(dir) = dir else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(file) = resolve(&dir, &path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(bytes) = tokio::fs::read(&file).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(&file)),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // An SVG opened directly must not be able to run script.
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_serves_files_and_refuses_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("static");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("img")).unwrap();
        std::fs::write(root.join("a.css"), "body{}").unwrap();
        std::fs::write(root.join("img/logo.png"), "p").unwrap();
        std::fs::write(tmp.path().join("secret.txt"), "s").unwrap();

        assert!(resolve(&root, "a.css").await.is_some());
        assert!(resolve(&root, "img/logo.png").await.is_some());
        assert!(resolve(&root, "../secret.txt").await.is_none());
        assert!(resolve(&root, "/etc/passwd").await.is_none());
        assert!(resolve(&root, "missing.css").await.is_none());
    }

    #[tokio::test]
    async fn test_resolve_refuses_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("static");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(tmp.path().join("secret.txt"), "s").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("secret.txt"), root.join("link.txt")).unwrap();
        assert!(resolve(&root, "link.txt").await.is_none());
    }

    #[test]
    fn test_content_type() {
        assert_eq!(content_type(Path::new("x.CSS")), "text/css; charset=utf-8");
        assert_eq!(content_type(Path::new("x.bin")), "application/octet-stream");
    }
}
