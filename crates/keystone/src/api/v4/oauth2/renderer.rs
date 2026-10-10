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

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use minijinja::value::{Kwargs, Value};
use minijinja::{Environment, context};
use serde::Serialize;
use thiserror::Error;

use openstack_keystone_config::Oauth2Provider;
use openstack_keystone_core_types::oauth2_client::OAuth2ClientResource;

/// Template names understood by the renderer. Each is looked up in
/// `templates_dir` first and falls back to the embedded default.
const TEMPLATES: &[(&str, &str)] = &[
    (
        "base.html",
        include_str!("../../../../templates/oauth2/base.html"),
    ),
    (
        "login.html",
        include_str!("../../../../templates/oauth2/login.html"),
    ),
    (
        "consent.html",
        include_str!("../../../../templates/oauth2/consent.html"),
    ),
    (
        "logout.html",
        include_str!("../../../../templates/oauth2/logout.html"),
    ),
    (
        "mfa.html",
        include_str!("../../../../templates/oauth2/mfa.html"),
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

/// Default stylesheet, served at `/v4/oauth2/static/style.css` unless
/// `static_dir` provides its own.
pub(super) const DEFAULT_STYLESHEET: &str = include_str!("../../../../templates/oauth2/style.css");

const DEFAULT_LOCALE_EN: &str = include_str!("../../../../templates/oauth2/locales/en.toml");

#[derive(Debug, Error)]
pub(crate) enum RendererError {
    #[error("invalid locale file {name}: {message}")]
    Locale { name: String, message: String },
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

/// Operator branding, exposed to every template as `branding`.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Branding {
    pub product_name: String,
    pub logo_url: Option<String>,
    pub support_url: Option<String>,
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
}

impl From<&Oauth2Provider> for Branding {
    fn from(cfg: &Oauth2Provider) -> Self {
        Self {
            product_name: cfg.ui_product_name.clone(),
            logo_url: cfg.ui_logo_url.clone(),
            support_url: cfg.ui_support_url.clone(),
            privacy_url: cfg.ui_privacy_url.clone(),
            terms_url: cfg.ui_terms_url.clone(),
        }
    }
}

tokio::task_local! {
    /// Raw `Accept-Language` header of the request being served, set by
    /// [`locale_middleware`] so that pages can be localised without
    /// threading the header through every handler.
    static ACCEPT_LANGUAGE: Option<String>;
}

/// Middleware recording the request's `Accept-Language` for the renderer.
pub(super) async fn locale_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let header = request
        .headers()
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // OIDC Core §3.1.2.1 `ui_locales`: the RP's preferred languages, most
    // preferred first, ahead of the browser's own preference.
    let ui_locales = request.uri().query().and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "ui_locales")
            .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>().join(", "))
            .filter(|v| !v.is_empty())
    });
    let value = match (ui_locales, header) {
        (Some(ui), Some(header)) => Some(format!("{ui}, {header}")),
        (Some(ui), None) => Some(ui),
        (None, header) => header,
    };
    ACCEPT_LANGUAGE.scope(value, next.run(request)).await
}

/// Locale name -> (string key -> text).
#[derive(Debug)]
struct Locales {
    bundles: HashMap<String, HashMap<String, String>>,
    default: String,
}

impl Locales {
    fn load(dir: Option<&Path>, default: &str) -> Result<Self, RendererError> {
        fn parse(name: &str, text: &str) -> Result<HashMap<String, String>, RendererError> {
            toml::from_str(text).map_err(|e| RendererError::Locale {
                name: name.to_string(),
                message: e.to_string(),
            })
        }
        let mut bundles = HashMap::new();
        bundles.insert("en".to_string(), parse("en", DEFAULT_LOCALE_EN)?);
        let locales_dir = dir.map(|d| d.join("locales")).filter(|d| d.exists());
        if let Some(dir) = locales_dir {
            let entries = std::fs::read_dir(&dir).map_err(|source| RendererError::Read {
                name: dir.display().to_string(),
                source,
            })?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                    continue;
                }
                let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let text =
                    std::fs::read_to_string(&path).map_err(|source| RendererError::Read {
                        name: path.display().to_string(),
                        source,
                    })?;
                // An operator file extends or overrides the built-in
                // bundle of the same name.
                let mut parsed = parse(name, &text)?;
                if let Some(existing) = bundles.remove(&name.to_ascii_lowercase()) {
                    let mut merged = existing;
                    merged.extend(parsed.drain());
                    parsed = merged;
                }
                bundles.insert(name.to_ascii_lowercase(), parsed);
            }
        }
        let default = default.to_ascii_lowercase();
        let default = if bundles.contains_key(&default) {
            default
        } else {
            "en".to_string()
        };
        Ok(Self { bundles, default })
    }

    /// Pick the best available locale for an `Accept-Language` value:
    /// highest `q` first, exact tag before its primary subtag, then the
    /// configured default.
    fn negotiate(&self, accept_language: Option<&str>) -> &str {
        let mut wanted: Vec<(f32, String)> = accept_language
            .unwrap_or_default()
            .split(',')
            .filter_map(|part| {
                let mut it = part.trim().split(';');
                let tag = it.next()?.trim().to_ascii_lowercase();
                if tag.is_empty() || tag == "*" {
                    return None;
                }
                let q = it
                    .find_map(|p| {
                        p.trim()
                            .strip_prefix("q=")
                            .and_then(|q| q.parse::<f32>().ok())
                    })
                    .unwrap_or(1.0);
                (q > 0.0).then_some((q, tag))
            })
            .collect();
        wanted.sort_by(|a, b| b.0.total_cmp(&a.0));
        for (_, tag) in wanted {
            if let Some((name, _)) = self.bundles.get_key_value(&tag) {
                return name;
            }
            if let Some(primary) = tag.split('-').next()
                && let Some((name, _)) = self.bundles.get_key_value(primary)
            {
                return name;
            }
        }
        &self.default
    }

    fn lookup(&self, locale: &str, key: &str) -> String {
        self.bundles
            .get(locale)
            .and_then(|b| b.get(key))
            .or_else(|| self.bundles.get("en").and_then(|b| b.get(key)))
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }
}

static SHOW_CLIENT_LOGOS: AtomicBool = AtomicBool::new(false);

/// Whether client-supplied logos are rendered (and the CSP allows loading
/// them): `[oauth2] ui_show_client_logos`.
pub(crate) fn show_client_logos() -> bool {
    SHOW_CLIENT_LOGOS.load(Ordering::Relaxed)
}

/// The registered client as shown to the user.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ClientView {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Only set when `ui_show_client_logos` is on.
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
}

impl ClientView {
    /// Fallback for a client that cannot be looked up: show its id.
    pub(crate) fn from_id(client_id: &str) -> Self {
        Self {
            id: client_id.to_string(),
            name: client_id.to_string(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
        }
    }

    pub(crate) fn from_resource(client: &OAuth2ClientResource) -> Self {
        // Registration only accepts https URLs (the scheme is matched
        // case-insensitively there); link only those regardless.
        let https = |u: &Option<String>| {
            u.clone().filter(|u| {
                u.get(..8)
                    .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
            })
        };
        Self {
            id: client.client_id.clone(),
            name: client.display_name().to_string(),
            description: client.description.clone(),
            logo_uri: if show_client_logos() {
                https(&client.logo_uri)
            } else {
                None
            },
            policy_uri: https(&client.policy_uri),
            tos_uri: https(&client.tos_uri),
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
    /// Upstream identity providers offered next to the password form.
    pub idps: Vec<IdpView>,
    /// Form target of the "Sign in with ..." buttons.
    pub federated_action: String,
    /// Prefilled username (OIDC `login_hint`).
    pub login_hint: Option<String>,
}

/// An upstream identity provider as the login page shows it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct IdpView {
    pub id: String,
    pub name: String,
}

/// Context of `mfa.html`.
#[derive(Debug, Serialize)]
pub(crate) struct MfaCtx {
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

/// Context of `logout.html`.
#[derive(Debug, Serialize)]
pub(crate) struct LogoutCtx {
    /// `true`: ask the user to confirm; `false`: report that they are signed
    /// out.
    pub confirm: bool,
    /// Form target of the confirmation.
    pub action: String,
    /// Request parameters carried through the confirmation form.
    pub fields: Vec<(String, String)>,
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
    fn render_mfa(&self, ctx: &MfaCtx) -> Result<String, minijinja::Error>;
    fn render_logout(&self, ctx: &LogoutCtx) -> Result<String, minijinja::Error>;
    fn render_device_entry(&self, ctx: &DeviceEntryCtx) -> Result<String, minijinja::Error>;
    fn render_device_result(&self, ctx: &DeviceResultCtx) -> Result<String, minijinja::Error>;
    fn render_error(&self, ctx: &ErrorCtx) -> Result<String, minijinja::Error>;
}

/// [`Renderer`] backed by a `minijinja` environment.
pub(crate) struct JinjaRenderer {
    env: Environment<'static>,
    branding: Branding,
    locales: Arc<Locales>,
}

impl JinjaRenderer {
    /// Built-in templates and the default configuration.
    pub(crate) fn embedded() -> Self {
        // The embedded templates are validated by the unit tests.
        Self::new(&Oauth2Provider::default()).unwrap_or_else(|_| Self {
            env: Environment::new(),
            branding: Branding::from(&Oauth2Provider::default()),
            locales: Arc::new(Locales {
                bundles: HashMap::new(),
                default: "en".to_string(),
            }),
        })
    }

    /// Built-in templates, overridden by files in `[oauth2] templates_dir`
    /// where present.
    pub(crate) fn new(cfg: &Oauth2Provider) -> Result<Self, RendererError> {
        let dir = cfg.templates_dir.as_deref();
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
        Ok(Self {
            env,
            branding: Branding::from(cfg),
            locales: Arc::new(Locales::load(dir, &cfg.ui_default_locale)?),
        })
    }

    fn render<S: Serialize>(&self, name: &str, ctx: &S) -> Result<String, minijinja::Error> {
        let accept = ACCEPT_LANGUAGE.try_with(Clone::clone).ok().flatten();
        let locale = self.locales.negotiate(accept.as_deref()).to_string();
        let locales = self.locales.clone();
        let locale_for_t = locale.clone();
        // `t("key", name=value)`: translated text with `{name}` placeholders
        // filled in; an unknown key is returned unchanged.
        let t = Value::from_function(move |key: &str, kwargs: Kwargs| {
            let mut text = locales.lookup(&locale_for_t, key);
            for arg in kwargs.args() {
                if let Ok(value) = kwargs.get::<Value>(arg) {
                    text = text.replace(&format!("{{{arg}}}"), &value.to_string());
                }
            }
            Ok::<_, minijinja::Error>(text)
        });
        self.env.get_template(name)?.render(context! {
            branding => &self.branding,
            locale => locale,
            t => t,
            ..Value::from_serialize(ctx)
        })
    }
}

impl Renderer for JinjaRenderer {
    fn render_login(&self, ctx: &LoginCtx) -> Result<String, minijinja::Error> {
        self.render("login.html", ctx)
    }
    fn render_consent(&self, ctx: &ConsentCtx) -> Result<String, minijinja::Error> {
        self.render("consent.html", ctx)
    }
    fn render_mfa(&self, ctx: &MfaCtx) -> Result<String, minijinja::Error> {
        self.render("mfa.html", ctx)
    }
    fn render_logout(&self, ctx: &LogoutCtx) -> Result<String, minijinja::Error> {
        self.render("logout.html", ctx)
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

/// Build the renderer for a configuration: operator templates and locales
/// from `templates_dir` where present, the embedded defaults otherwise.
pub(crate) fn renderer_from_config(
    cfg: &Oauth2Provider,
) -> Result<Arc<dyn Renderer>, RendererError> {
    Ok(Arc::new(JinjaRenderer::new(cfg)?))
}

static RENDERER: OnceLock<Arc<dyn Renderer>> = OnceLock::new();

/// Install the process-wide renderer. Called once at startup, after the
/// configuration is validated; later calls are ignored.
pub(crate) fn install(renderer: Arc<dyn Renderer>, show_logos: bool) {
    SHOW_CLIENT_LOGOS.store(show_logos, Ordering::Relaxed);
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
            login_hint: Default::default(),
            federated_action: Default::default(),
            idps: Default::default(),
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
        assert!(html.contains(">bad</p>"));
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
    fn test_pages_have_viewport_lang_and_branding() {
        let cfg = Oauth2Provider {
            ui_product_name: "Acme <Cloud>".into(),
            ui_logo_url: Some("/v4/oauth2/static/logo.svg".into()),
            ui_privacy_url: Some("https://acme.example/privacy".into()),
            ..Default::default()
        };
        let r = JinjaRenderer::new(&cfg).unwrap();
        let client = || ClientView::from_id("c");
        let pages = [
            r.render_login(&LoginCtx {
                login_hint: Default::default(),
                federated_action: Default::default(),
                idps: Default::default(),
                client: client(),
                csrf_token: "t".into(),
                error: None,
                action: "/a".into(),
            })
            .unwrap(),
            r.render_consent(&ConsentCtx {
                client: client(),
                scopes: vec![],
                csrf_token: "t".into(),
                action: "/a".into(),
            })
            .unwrap(),
            r.render_device_entry(&DeviceEntryCtx {
                error: Some("invalid or expired code".into()),
                prefill: String::new(),
                action: "/a".into(),
            })
            .unwrap(),
            r.render_device_result(&DeviceResultCtx {
                granted: true,
                client: client(),
            })
            .unwrap(),
            r.render_error(&ErrorCtx {
                message: "m".into(),
            })
            .unwrap(),
        ];
        for html in pages {
            assert!(html.contains(
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            ));
            assert!(html.contains("<html lang=\"en\">"));
            assert!(html.contains("Acme &lt;Cloud&gt;"));
            assert!(
                html.contains("src=\"&#x2f;v4&#x2f;oauth2&#x2f;static&#x2f;logo.svg\"")
                    || html.contains("src=\"/v4/oauth2/static/logo.svg\"")
            );
            assert!(html.contains("static/style.css") || html.contains("static&#x2f;style.css"));
            assert!(html.contains("Privacy"));
            assert!(!html.contains("Support"));
        }
    }

    fn rich_client(logo: bool) -> ClientView {
        ClientView {
            id: "id-1".into(),
            name: "Fancy <App>".into(),
            description: Some("Does things".into()),
            logo_uri: logo.then(|| "https://rp.example.com/logo.png".to_string()),
            policy_uri: Some("https://rp.example.com/privacy".into()),
            tos_uri: Some("https://rp.example.com/tos".into()),
        }
    }

    #[test]
    fn test_consent_shows_client_metadata() {
        let r = JinjaRenderer::embedded();
        let ctx = |logo| ConsentCtx {
            client: rich_client(logo),
            scopes: vec!["openid".into()],
            csrf_token: "t".into(),
            action: "/a".into(),
        };
        let with_logo = r.render_consent(&ctx(true)).unwrap();
        assert!(with_logo.contains("Fancy &lt;App&gt;"));
        assert!(!with_logo.contains("id-1"));
        assert!(with_logo.contains("Does things"));
        assert!(with_logo.contains("class=\"client-logo\""));
        assert!(with_logo.contains("rp.example.com&#x2f;logo.png"));
        assert!(with_logo.contains("rp.example.com&#x2f;privacy"));
        assert!(with_logo.contains("rp.example.com&#x2f;tos"));

        let without = r.render_consent(&ctx(false)).unwrap();
        assert!(!without.contains("client-logo\""));
        assert!(without.contains("Fancy &lt;App&gt;"));

        let login = r
            .render_login(&LoginCtx {
                login_hint: Default::default(),
                federated_action: Default::default(),
                idps: Default::default(),
                client: rich_client(true),
                csrf_token: "t".into(),
                error: None,
                action: "/a".into(),
            })
            .unwrap();
        assert!(login.contains("Fancy &lt;App&gt;"));
        assert!(login.contains("class=\"client-logo\""));
    }

    #[test]
    fn test_client_view_from_resource() {
        use openstack_keystone_core_types::oauth2_client::OAuth2ClientResource;
        let mut client = OAuth2ClientResource {
            post_logout_redirect_uris: Default::default(),
            client_id: "cid".into(),
            provider_id: "prov".into(),
            domain_id: "d".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![],
            require_pkce: true,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: String::new(),
            description: None,
            logo_uri: Some("https://rp.example.com/l.png".into()),
            policy_uri: Some("http://insecure.example.com/p".into()),
            tos_uri: None,
            contacts: vec![],
        };
        // Pre-existing records without a name show the provider id.
        let view = ClientView::from_resource(&client);
        assert_eq!(view.name, "prov");
        assert_eq!(view.id, "cid");
        // Logos are off by default; non-https links are never rendered.
        assert!(view.logo_uri.is_none());
        assert!(view.policy_uri.is_none());
        // The URL parser accepts an upper-case scheme at registration.
        client.policy_uri = Some("HTTPS://rp.example.com/p".into());
        assert!(ClientView::from_resource(&client).policy_uri.is_some());
        client.name = "Named".into();
        assert_eq!(ClientView::from_resource(&client).name, "Named");
    }

    #[test]
    fn test_mfa_page() {
        let r = JinjaRenderer::embedded();
        let html = r
            .render_mfa(&MfaCtx {
                client: ClientView::from_id("c"),
                csrf_token: "tok".into(),
                error: Some("invalid verification code".into()),
                action: "/v4/oauth2/d/authorize/mfa".into(),
            })
            .unwrap();
        assert!(html.contains("name=\"passcode\""));
        assert!(html.contains("autocomplete=\"one-time-code\""));
        assert!(html.contains("name=\"factor\" value=\"totp\""));
        assert!(html.contains("value=\"tok\""));
        assert!(html.contains(">invalid verification code</p>"));
    }

    #[test]
    fn test_accessibility_hooks() {
        let r = JinjaRenderer::embedded();
        let login = r.render_login(&login_ctx()).unwrap();
        assert!(login.contains("<label for=\"username\">"));
        assert!(login.contains("id=\"username\""));
        assert!(login.contains("autofocus"));
        assert!(login.contains("aria-live=\"polite\""));
        let entry = r
            .render_device_entry(&DeviceEntryCtx {
                error: None,
                prefill: String::new(),
                action: "/a".into(),
            })
            .unwrap();
        assert!(entry.contains("autocapitalize=\"characters\""));
        assert!(entry.contains("inputmode=\"text\""));
        let pattern = entry
            .split("pattern=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_default()
            .to_string();
        // Server-issued user codes look like `BCDF-2345`.
        assert_eq!(pattern, "[A-Za-z0-9\\-]+");
    }

    #[test]
    fn test_locale_negotiation_and_operator_locale() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("locales")).unwrap();
        std::fs::write(
            dir.path().join("locales/de.toml"),
            "sign_in = \"Anmelden\"\nrequesting_access = \"{client} moechte Zugriff.\"\n",
        )
        .unwrap();
        let cfg = Oauth2Provider {
            templates_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let r = JinjaRenderer::new(&cfg).unwrap();
        assert_eq!(r.locales.negotiate(None), "en");
        assert_eq!(r.locales.negotiate(Some("de-CH, en;q=0.5")), "de");
        assert_eq!(r.locales.negotiate(Some("fr, en;q=0.5")), "en");
        assert_eq!(r.locales.negotiate(Some("en;q=0.2, de;q=0.9")), "de");
        assert_eq!(r.locales.negotiate(Some("de;q=0")), "en");

        // Without a request scope the default locale is used.
        assert!(r.render_login(&login_ctx()).unwrap().contains("Sign in"));
        let de = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(ACCEPT_LANGUAGE.scope(Some("de".into()), async {
                r.render_login(&login_ctx()).unwrap()
            }));
        assert!(de.contains("<html lang=\"de\">"));
        assert!(de.contains("Anmelden"));
        // The client name is escaped; untranslated keys fall back to English.
        assert!(de.contains("&lt;b&gt;app&lt;&#x2f;b&gt; moechte Zugriff."));
        assert!(de.contains("Username"));
    }

    #[test]
    fn test_invalid_locale_file_fails_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("locales")).unwrap();
        std::fs::write(dir.path().join("locales/xx.toml"), "not toml =").unwrap();
        let cfg = Oauth2Provider {
            templates_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert!(matches!(
            JinjaRenderer::new(&cfg),
            Err(RendererError::Locale { .. })
        ));
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
            JinjaRenderer::new(&Oauth2Provider {
                templates_dir: Some(dir.path().to_path_buf()),
                ..Default::default()
            }),
            Err(RendererError::Template { .. })
        ));
    }
}
