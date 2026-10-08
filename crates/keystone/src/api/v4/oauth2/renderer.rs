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
//! Page rendering for the human-facing OAuth2 flows (ADR 0026 §8).
//!
//! Every page goes through a [`Renderer`]. The built-in implementation
//! embeds the default templates; when `[oauth2] templates_dir` is set, any
//! page found there replaces the built-in one (the rest fall back), so an
//! operator can rebrand a single page without a rebuild.
//!
//! Templates use the Jinja syntax (`minijinja`) with HTML autoescaping. The
//! context variables per page are the fields of the `*Ctx` structs below.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use minijinja::Environment;
use serde::Serialize;
use thiserror::Error;

use openstack_keystone_config::Oauth2Provider;

/// Template names understood by the renderer. Each is looked up in
/// `templates_dir` first and falls back to the embedded default.
const TEMPLATES: &[(&str, &str)] = &[
    (
        "login.html",
        include_str!("../../../../templates/oauth2/login.html"),
    ),
    (
        "consent.html",
        include_str!("../../../../templates/oauth2/consent.html"),
    ),
    (
        "device_entry.html",
        include_str!("../../../../templates/oauth2/device_entry.html"),
    ),
    (
        "device_result.html",
        include_str!("../../../../templates/oauth2/device_result.html"),
    ),
    (
        "error.html",
        include_str!("../../../../templates/oauth2/error.html"),
    ),
];

#[derive(Debug, Error)]
pub(crate) enum RendererError {
    #[error("cannot read template {name}: {source}")]
    Read {
        name: String,
        source: std::io::Error,
    },
    #[error("template {name}: {source}")]
    Template {
        name: String,
        source: minijinja::Error,
    },
}

/// The registered client as shown to the user.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ClientView {
    pub id: String,
    pub name: String,
}

impl ClientView {
    pub(crate) fn from_id(client_id: &str) -> Self {
        Self {
            id: client_id.to_string(),
            name: client_id.to_string(),
        }
    }
}

/// Context of `login.html`.
#[derive(Debug, Serialize)]
pub(crate) struct LoginCtx {
    pub client: ClientView,
    pub csrf_token: String,
    pub error: Option<String>,
    pub action: String,
}

/// Context of `consent.html`.
#[derive(Debug, Serialize)]
pub(crate) struct ConsentCtx {
    pub client: ClientView,
    pub scopes: Vec<String>,
    pub csrf_token: String,
    pub action: String,
}

/// Context of `device_entry.html`.
#[derive(Debug, Serialize)]
pub(crate) struct DeviceEntryCtx {
    pub error: Option<String>,
    pub prefill: String,
    pub action: String,
}

/// Context of `device_result.html`.
#[derive(Debug, Serialize)]
pub(crate) struct DeviceResultCtx {
    pub granted: bool,
    pub client: ClientView,
}

/// Context of `error.html`.
#[derive(Debug, Serialize)]
pub(crate) struct ErrorCtx {
    pub message: String,
}

/// Renders the OAuth2 browser pages.
pub(crate) trait Renderer: Send + Sync {
    fn render_login(&self, ctx: &LoginCtx) -> Result<String, minijinja::Error>;
    fn render_consent(&self, ctx: &ConsentCtx) -> Result<String, minijinja::Error>;
    fn render_device_entry(&self, ctx: &DeviceEntryCtx) -> Result<String, minijinja::Error>;
    fn render_device_result(&self, ctx: &DeviceResultCtx) -> Result<String, minijinja::Error>;
    fn render_error(&self, ctx: &ErrorCtx) -> Result<String, minijinja::Error>;
}

/// [`Renderer`] backed by a `minijinja` environment.
pub(crate) struct JinjaRenderer {
    env: Environment<'static>,
}

impl JinjaRenderer {
    /// Built-in templates only.
    pub(crate) fn embedded() -> Self {
        // The embedded templates are validated by the unit tests.
        Self::build(None).unwrap_or_else(|_| Self {
            env: Environment::new(),
        })
    }

    /// Built-in templates, overridden by files in `dir` where present.
    pub(crate) fn from_dir(dir: &Path) -> Result<Self, RendererError> {
        Self::build(Some(dir))
    }

    fn build(dir: Option<&Path>) -> Result<Self, RendererError> {
        let mut env = Environment::new();
        for (name, default) in TEMPLATES {
            let source = match dir.map(|d| d.join(name)) {
                Some(path) if path.is_file() => {
                    std::fs::read_to_string(&path).map_err(|source| RendererError::Read {
                        name: (*name).to_string(),
                        source,
                    })?
                }
                _ => (*default).to_string(),
            };
            env.add_template_owned(*name, source)
                .map_err(|source| RendererError::Template {
                    name: (*name).to_string(),
                    source,
                })?;
        }
        Ok(Self { env })
    }

    fn render<S: Serialize>(&self, name: &str, ctx: &S) -> Result<String, minijinja::Error> {
        self.env.get_template(name)?.render(ctx)
    }
}

impl Renderer for JinjaRenderer {
    fn render_login(&self, ctx: &LoginCtx) -> Result<String, minijinja::Error> {
        self.render("login.html", ctx)
    }
    fn render_consent(&self, ctx: &ConsentCtx) -> Result<String, minijinja::Error> {
        self.render("consent.html", ctx)
    }
    fn render_device_entry(&self, ctx: &DeviceEntryCtx) -> Result<String, minijinja::Error> {
        self.render("device_entry.html", ctx)
    }
    fn render_device_result(&self, ctx: &DeviceResultCtx) -> Result<String, minijinja::Error> {
        self.render("device_result.html", ctx)
    }
    fn render_error(&self, ctx: &ErrorCtx) -> Result<String, minijinja::Error> {
        self.render("error.html", ctx)
    }
}

/// Select the renderer for a configuration: operator templates when
/// `templates_dir` is set, the embedded defaults otherwise.
pub(crate) fn renderer_from_config(
    cfg: &Oauth2Provider,
) -> Result<Arc<dyn Renderer>, RendererError> {
    match &cfg.templates_dir {
        Some(dir) => Ok(Arc::new(JinjaRenderer::from_dir(dir)?)),
        None => Ok(Arc::new(JinjaRenderer::embedded())),
    }
}

static RENDERER: OnceLock<Arc<dyn Renderer>> = OnceLock::new();

/// Install the process-wide renderer. Called once at startup, after the
/// configuration is validated; later calls are ignored.
pub(crate) fn install(renderer: Arc<dyn Renderer>) {
    let _ = RENDERER.set(renderer);
}

/// The installed renderer, or the embedded defaults when none was installed
/// (tests, `--dump-openapi`).
pub(crate) fn renderer() -> Arc<dyn Renderer> {
    RENDERER
        .get_or_init(|| Arc::new(JinjaRenderer::embedded()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_ctx() -> LoginCtx {
        LoginCtx {
            client: ClientView::from_id("<b>app</b>"),
            csrf_token: "tok".into(),
            error: Some("bad".into()),
            action: "/x".into(),
        }
    }

    #[test]
    fn test_embedded_templates_compile_and_escape() {
        let r = JinjaRenderer::embedded();
        let html = r.render_login(&login_ctx()).unwrap();
        assert!(html.contains("&lt;b&gt;app&lt;&#x2f;b&gt;"));
        assert!(html.contains("class=\"error\""));
        assert!(html.contains("value=\"tok\""));
        assert!(
            r.render_consent(&ConsentCtx {
                client: ClientView::from_id("c"),
                scopes: vec!["openid".into()],
                csrf_token: "t".into(),
                action: "/a".into(),
            })
            .unwrap()
            .contains("<li>openid</li>")
        );
        assert!(
            r.render_device_entry(&DeviceEntryCtx {
                error: None,
                prefill: "AB-CD".into(),
                action: "/d".into(),
            })
            .unwrap()
            .contains("AB-CD")
        );
        assert!(
            r.render_device_result(&DeviceResultCtx {
                granted: false,
                client: ClientView::from_id("c"),
            })
            .unwrap()
            .contains("Request denied")
        );
        assert!(
            r.render_error(&ErrorCtx {
                message: "boom".into()
            })
            .unwrap()
            .contains("boom")
        );
    }

    #[test]
    fn test_renderer_selection_by_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("login.html"), "custom {{ client.name }}").unwrap();
        let cfg = Oauth2Provider {
            templates_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let r = renderer_from_config(&cfg).unwrap();
        // Overridden page uses the operator template ...
        assert_eq!(
            r.render_login(&login_ctx()).unwrap(),
            "custom &lt;b&gt;app&lt;&#x2f;b&gt;"
        );
        // ... the rest fall back to the built-in default.
        assert!(
            r.render_error(&ErrorCtx {
                message: "m".into()
            })
            .unwrap()
            .contains("Sign-in error")
        );

        let r = renderer_from_config(&Oauth2Provider::default()).unwrap();
        assert!(r.render_login(&login_ctx()).unwrap().contains("Sign in"));
    }

    #[test]
    fn test_invalid_operator_template_fails_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("error.html"), "{% if %}").unwrap();
        assert!(matches!(
            JinjaRenderer::from_dir(dir.path()),
            Err(RendererError::Template { .. })
        ));
    }
}
