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
use httpmock::prelude::*;
use openstack_keystone_storage_crypto::site_wrap::{
    SiteBinding, SoftwareSiteKey, unwrap_dek_for_site, wrap_dek_for_site,
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

use super::*;

/// Drive an async call to completion from a synchronous test.
fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn params(server: &MockServer, auth: TransitAuth) -> TransitParams {
    openstack_keystone_tls_provider::install_default();
    TransitParams {
        address: Url::parse(&server.base_url()).unwrap(),
        auth,
        ca_pem: None,
        mount: "transit".into(),
        namespace: None,
        timeout: Duration::from_secs(5),
    }
}

fn token_auth() -> TransitAuth {
    TransitAuth::Token(SecretString::from("s.token".to_owned()))
}

fn plaintext_for(dek: &[u8; 32]) -> String {
    let mut p = DEK_WRAP_AD.to_vec();
    p.extend_from_slice(dek);
    B64.encode(p)
}

#[test]
fn wrap_and_unwrap_dek() {
    let server = MockServer::start();
    let dek = [9u8; 32];
    let enc = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/transit/encrypt/kek")
            .header("X-Vault-Token", "s.token")
            .json_body(json!({"plaintext": plaintext_for(&dek)}));
        then.status(200)
            .json_body(json!({"data": {"ciphertext": "vault:v1:abc"}}));
    });
    let dec = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/transit/decrypt/kek")
            .json_body(json!({"ciphertext": "vault:v1:abc"}));
        then.status(200)
            .json_body(json!({"data": {"plaintext": plaintext_for(&dek)}}));
    });
    let kek = TransitKek::new(params(&server, token_auth()), "kek").unwrap();
    let wrapped = run(kek.wrap_dek(&dek)).unwrap();
    assert_eq!(wrapped, b"vault:v1:abc");
    assert_eq!(*run(kek.unwrap_dek(&wrapped)).unwrap(), dek);
    enc.assert();
    dec.assert();
}

#[test]
fn unwrap_rejects_foreign_plaintext_and_bad_blobs() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/decrypt/kek");
        then.status(200)
            .json_body(json!({"data": {"plaintext": B64.encode([1u8; 32])}}));
    });
    let kek = TransitKek::new(params(&server, token_auth()), "kek").unwrap();
    // Plaintext without the binding prefix.
    assert!(run(kek.unwrap_dek(b"vault:v1:abc")).is_err());
    // Not a Transit ciphertext at all: no request is made.
    assert!(matches!(
        run(kek.unwrap_dek(b"not-transit")),
        Err(CryptoError::WrappedDekSize)
    ));
}

#[test]
fn errors_from_openbao_are_reported() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/kek");
        then.status(500).body("boom");
    });
    let kek = TransitKek::new(params(&server, token_auth()), "kek").unwrap();
    let err = run(kek.wrap_dek(&[0u8; 32])).unwrap_err().to_string();
    assert!(err.contains("500"), "{err}");

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/kek");
        then.status(403).body("denied");
    });
    let kek = TransitKek::new(params(&server, token_auth()), "kek").unwrap();
    assert!(
        run(kek.wrap_dek(&[0u8; 32]))
            .unwrap_err()
            .to_string()
            .contains("403")
    );
}

fn jwt_auth() -> TransitAuth {
    TransitAuth::Jwt {
        mount: "jwt".into(),
        role: "keystone".into(),
        jwt: Box::new(|| Ok(SecretString::from("the.jwt".to_owned()))),
    }
}

fn login_mock(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(POST)
            .path("/v1/auth/jwt/login")
            .json_body(json!({"role": "keystone", "jwt": "the.jwt"}));
        then.status(200)
            .json_body(json!({"auth": {"client_token": "s.fresh"}}));
    })
}

#[test]
fn jwt_login_provides_the_token_once() {
    let server = MockServer::start();
    let login = login_mock(&server);
    let ok = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/transit/encrypt/kek")
            .header("X-Vault-Token", "s.fresh");
        then.status(200)
            .json_body(json!({"data": {"ciphertext": "vault:v2:x"}}));
    });
    let kek = TransitKek::new(params(&server, jwt_auth()), "kek").unwrap();
    assert_eq!(run(kek.wrap_dek(&[1u8; 32])).unwrap(), b"vault:v2:x");
    assert_eq!(run(kek.wrap_dek(&[1u8; 32])).unwrap(), b"vault:v2:x");
    assert_eq!(login.calls(), 1);
    assert_eq!(ok.calls(), 2);
}

#[test]
fn jwt_login_is_repeated_once_after_403() {
    let server = MockServer::start();
    let login = login_mock(&server);
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/kek");
        then.status(403);
    });
    let kek = TransitKek::new(params(&server, jwt_auth()), "kek").unwrap();
    let err = run(kek.wrap_dek(&[1u8; 32])).unwrap_err().to_string();
    assert!(err.contains("403"), "{err}");
    // First login, then one more after the rejection; no loop.
    assert_eq!(login.calls(), 2);
}

fn identity_pem() -> Zeroizing<Vec<u8>> {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["keystone.test".to_owned()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let mut pem = cert.pem().into_bytes();
    pem.extend_from_slice(key.serialize_pem().as_bytes());
    Zeroizing::new(pem)
}

#[test]
fn cert_login_uses_the_identity_and_is_repeated_once_after_403() {
    let server = MockServer::start();
    let logins = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/auth/cert/login")
            .json_body(json!({"name": "keystone"}));
        then.status(200)
            .json_body(json!({"auth": {"client_token": "s.cert"}}));
    });
    let ok = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/transit/encrypt/kek")
            .header("X-Vault-Token", "s.cert");
        then.status(200)
            .json_body(json!({"data": {"ciphertext": "vault:v1:c"}}));
    });
    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = fetched.clone();
    let auth = TransitAuth::Cert {
        mount: "cert".into(),
        role: Some("keystone".into()),
        identity: Box::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(identity_pem())
        }),
    };
    let kek = TransitKek::new(params(&server, auth), "kek").unwrap();
    assert_eq!(run(kek.wrap_dek(&[1u8; 32])).unwrap(), b"vault:v1:c");
    assert_eq!(logins.calls(), 1);
    assert_eq!(ok.calls(), 1);
    assert_eq!(fetched.load(std::sync::atomic::Ordering::SeqCst), 1);

    // A rejected token triggers one new login with a freshly fetched identity.
    let server = MockServer::start();
    let logins = server.mock(|when, then| {
        when.method(POST).path("/v1/auth/cert/login");
        then.status(200)
            .json_body(json!({"auth": {"client_token": "s.cert"}}));
    });
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/kek");
        then.status(403);
    });
    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = fetched.clone();
    let auth = TransitAuth::Cert {
        mount: "cert".into(),
        role: None,
        identity: Box::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(identity_pem())
        }),
    };
    let kek = TransitKek::new(params(&server, auth), "kek").unwrap();
    assert!(run(kek.wrap_dek(&[1u8; 32])).is_err());
    assert_eq!(logins.calls(), 2);
    assert_eq!(fetched.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn pem_identity_round_trips_through_reqwest() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["keystone.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = pem_identity(&[cert.der().as_ref()], &key.serialize_der());
    reqwest::Identity::from_pem(&pem).expect("identity parses");
}

#[test]
fn cert_login_rejects_a_malformed_identity() {
    let server = MockServer::start();
    let auth = TransitAuth::Cert {
        mount: "cert".into(),
        role: None,
        identity: Box::new(|| Ok(Zeroizing::new(b"not pem".to_vec()))),
    };
    let kek = TransitKek::new(params(&server, auth), "kek").unwrap();
    let err = run(kek.wrap_dek(&[1u8; 32])).unwrap_err().to_string();
    assert!(err.contains("client identity"), "{err}");
}

#[test]
fn site_key_decrypts_a_site_blob() {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let public = key.to_public_key().to_public_key_der().unwrap();
    let software = SoftwareSiteKey::from_pkcs8_der(key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let binding = SiteBinding {
        cluster_id: "c1",
        dek_version: 2,
        site: "eu-1",
    };
    let dek = [5u8; 32];
    let blob = wrap_dek_for_site(public.as_bytes(), &dek, &binding).unwrap();
    // What OpenBao's RSA decrypt would return: the OAEP plaintext.
    let plaintext = run(software.decrypt(&blob)).unwrap();

    let server = MockServer::start();
    let dec = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/transit/decrypt/site")
            .json_body(json!({"ciphertext": format!("vault:v3:{}", B64.encode(&blob))}));
        then.status(200)
            .json_body(json!({"data": {"plaintext": B64.encode(&*plaintext)}}));
    });
    let kek = TransitKek::new(params(&server, token_auth()), "kek").unwrap();
    let site = kek.site_key("site", 3);
    assert_eq!(
        *run(unwrap_dek_for_site(&site, &blob, &binding)).unwrap(),
        dek
    );
    dec.assert();
}

#[test]
fn server_errors_are_transient_and_client_errors_are_not() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/down");
        then.status(503).body("sealed");
    });
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/gone");
        then.status(400).body("no such key");
    });
    let down = TransitKek::new(params(&server, token_auth()), "down").unwrap();
    assert!(run(down.wrap_dek(&[0u8; 32])).unwrap_err().is_transient());
    let gone = TransitKek::new(params(&server, token_auth()), "gone").unwrap();
    assert!(!run(gone.wrap_dek(&[0u8; 32])).unwrap_err().is_transient());

    // Nothing listens here: the connection fails, which is transient.
    let mut p = params(&server, token_auth());
    p.address = Url::parse("http://127.0.0.1:1").unwrap();
    let unreachable = TransitKek::new(p, "down").unwrap();
    assert!(
        run(unreachable.wrap_dek(&[0u8; 32]))
            .unwrap_err()
            .is_transient()
    );
}

#[test]
fn a_permanent_403_with_a_fixed_token_is_not_transient() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/kek");
        then.status(403);
    });
    let kek = TransitKek::new(params(&server, token_auth()), "kek").unwrap();
    assert!(!run(kek.wrap_dek(&[0u8; 32])).unwrap_err().is_transient());
}

#[test]
fn a_denied_login_names_the_login() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/auth/jwt/login");
        then.status(403);
    });
    let kek = TransitKek::new(params(&server, jwt_auth()), "kek").unwrap();
    let err = run(kek.wrap_dek(&[0u8; 32])).unwrap_err();
    assert!(err.is_transient());
    assert!(err.to_string().contains("login to auth/jwt"), "{err}");
}

#[test]
fn redirects_are_not_followed() {
    let target = MockServer::start();
    let hit = target.mock(|when, then| {
        when.any_request();
        then.status(200).json_body(json!({"data": {}}));
    });
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/v1/transit/encrypt/kek");
        then.status(307)
            .header("Location", target.url("/v1/transit/encrypt/kek"));
    });
    let kek = TransitKek::new(params(&server, token_auth()), "kek").unwrap();
    let err = run(kek.wrap_dek(&[0u8; 32])).unwrap_err().to_string();
    assert!(err.contains("redirect"), "{err}");
    hit.assert_calls(0);
}

#[test]
fn address_prefix_is_kept_and_names_are_escaped() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(POST).path("/bao/v1/team/transit/encrypt/a%2Fb");
        then.status(200)
            .json_body(json!({"data": {"ciphertext": "vault:v1:x"}}));
    });
    let mut p = params(&server, token_auth());
    p.address = Url::parse(&server.url("/bao")).unwrap();
    p.mount = "/team/transit/".into();
    let kek = TransitKek::new(p, "a/b").unwrap();
    assert_eq!(run(kek.wrap_dek(&[0u8; 32])).unwrap(), b"vault:v1:x");
    m.assert();
}
