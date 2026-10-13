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
// SPDX-License-Identifier: Apache-2.0
//! Live-server sign-in UI customisation: operator templates, static
//! assets, branding and `ui_locales`. The server is started by
//! `tools/start-api.sh` with `templates_dir` / `static_dir` pointing at
//! `tests/api/fixtures/oauth2` and `ui_product_name = Fixture Cloud`.

use eyre::Result;
use reqwest::StatusCode;
use serde_json::json;
use tracing_test::traced_test;

use test_api::oauth2_browser::*;

const PRODUCT: &str = "Fixture Cloud";

struct Fixture {
    domain_id: String,
    client: BrowserClient,
    username: String,
}

async fn fixture(extra: serde_json::Value) -> Result<Fixture> {
    let domain_id = create_ready_domain("ui").await?;
    let client = create_browser_client(&domain_id, extra).await?;
    let (_, username) = create_browser_user(&domain_id).await?;
    Ok(Fixture {
        domain_id,
        client,
        username,
    })
}

async fn login_page(f: &Fixture, params: AuthorizeParams) -> Result<BrowserResponse> {
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let rsp = browser.authorize(&params).await?;
    assert!(rsp.is_login(), "{}: {}", rsp.status, rsp.body);
    Ok(rsp)
}

async fn static_get(path: &str) -> Result<reqwest::Response> {
    Ok(reqwest::get(base_url()?.join(&format!("v4/oauth2/static/{path}"))?).await?)
}

#[tokio::test]
#[traced_test]
async fn test_operator_login_template_is_used() -> Result<()> {
    let f = fixture(json!({})).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = login_page(&f, params).await?;
    assert!(
        rsp.body.contains("data-fixture=\"login-override\""),
        "{}",
        rsp.body
    );
    // The override still carries the client identity and the form.
    assert!(rsp.body.contains("browser test client"), "{}", rsp.body);
    assert!(rsp.csrf().is_ok());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_branding_is_applied_to_pages() -> Result<()> {
    let f = fixture(json!({})).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = login_page(&f, params.clone()).await?;
    assert!(rsp.body.contains(PRODUCT), "{}", rsp.body);
    assert!(rsp.body.contains("static&#x2f;logo.svg"), "{}", rsp.body);

    // A page without an operator template falls back to the built-in one,
    // still branded.
    let browser = AuthorizeBrowser::new(&f.domain_id)?;
    let rsp = browser.authorize(&params).await?;
    let consent = browser.login(&rsp.csrf()?, &f.username, PASSWORD).await?;
    assert!(consent.is_consent(), "{}: {}", consent.status, consent.body);
    assert!(consent.body.contains(PRODUCT), "{}", consent.body);
    assert!(
        consent.body.contains("browser test client"),
        "{}",
        consent.body
    );
    assert!(!consent.body.contains("data-fixture"), "{}", consent.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_static_assets_are_served() -> Result<()> {
    let css = static_get("style.css").await?;
    assert_eq!(css.status(), StatusCode::OK);
    assert!(
        css.headers()["content-type"]
            .to_str()?
            .starts_with("text/css"),
        "{:?}",
        css.headers()
    );
    assert!(css.text().await?.contains("fixture-style-override"));

    let logo = static_get("logo.svg").await?;
    assert_eq!(logo.status(), StatusCode::OK);
    assert_eq!(logo.headers()["content-type"], "image/svg+xml");
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_static_route_rejects_missing_and_escaping_paths() -> Result<()> {
    assert_eq!(
        static_get("missing.png").await?.status(),
        StatusCode::NOT_FOUND
    );
    for escape in [
        "..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2fCargo.toml",
        "..%2Ftemplates%2Flogin.html",
    ] {
        let status = static_get(escape).await?.status();
        assert!(status.is_client_error(), "{escape} served with {status}");
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_ui_locales_selects_translation() -> Result<()> {
    let f = fixture(json!({})).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = login_page(&f, params.clone().with("ui_locales", "de")).await?;
    assert!(rsp.body.contains("lang=\"de\""), "{}", rsp.body);
    assert!(rsp.body.contains("Anmelden-Fixture"), "{}", rsp.body);

    // First available entry of a preference list wins.
    let rsp = login_page(&f, params.clone().with("ui_locales", "xx de")).await?;
    assert!(rsp.body.contains("Anmelden-Fixture"), "{}", rsp.body);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_unknown_ui_locale_falls_back_to_default() -> Result<()> {
    let f = fixture(json!({})).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = login_page(&f, params.with("ui_locales", "xx")).await?;
    assert!(rsp.body.contains("lang=\"en\""), "{}", rsp.body);
    assert!(!rsp.body.contains("Anmelden-Fixture"));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_client_logo_is_not_loaded_by_default() -> Result<()> {
    let f = fixture(json!({"logo_uri": "https://rp.example.com/logo.png"})).await?;
    let (params, _) = AuthorizeParams::new(&f.client.client_id);
    let rsp = login_page(&f, params).await?;
    assert!(
        !rsp.body.contains("rp.example.com/logo.png"),
        "client logo rendered with ui_show_client_logos off: {}",
        rsp.body
    );
    Ok(())
}
