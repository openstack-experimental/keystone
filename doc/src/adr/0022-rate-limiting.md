# ADR 0022: Handler-Level Rate Limiting via Governor

Date: 2026-06-15

## Status

Proposed

## Context

The `keystone-rs` project (Keystone-NG) requires robust rate limiting to protect
against brute-force attacks, credential stuffing, and general API resource
exhaustion. The project currently utilizes the `axum` web framework for its HTTP
routing and request handling.

While the Rust ecosystem offers several middleware-based rate limiting solutions
(e.g., `tower` layers or `axum`-specific wrapper crates), evaluating these
reveals significant drawbacks:

- **Maintenance Decay:** Many wrapper crates are poorly maintained, tightly
  coupling our core security infrastructure to abandoned dependencies.
- **Inflexible Abstractions:** Middleware layers operate before the request
  reaches the handler. They struggle to apply limits based on complex,
  request-specific business logic.
- **Static Configuration Limitations:** Middleware often expects statically
  compiled limits, whereas operational environments demand dynamically
  configurable and toggleable rate limits via external configuration files.
- **Legacy Compatibility:** Configuration must be parsed from the existing
  `keystone.conf` INI file to ensure seamless co-existence with the legacy
  Python Keystone service (`oslo.config`).

We need a rate-limiting solution that:

- Uses heavily vetted, actively maintained dependencies (`governor` directly).
- Allows operators to define quotas or selectively disable limits entirely via
  the standard INI application configuration file.
- Is explicitly invoked within the `axum` handlers rather than globally.
- Emits standardized, RFC-compliant HTTP 429 error responses with `Retry-After`
  without leaking identifying information in headers.

This ADR complements ADR 0010 (account lockout). ADR 0010 protects against
brute-force by locking the user account after N failed attempts with a fixed
lockout duration governed by `conf.security_compliance`. Rate limiting per this
ADR operates independently: it throttles requests before they reach password
verification, protecting CPU resources and database load regardless of
authentication outcome. The two mechanisms are additive — rate limiting fires
first, then ADR 0010 lockout fires on repeated failures.

## Decision

We will implement rate limiting by utilizing the **`governor`** crate directly
within our `axum` handlers. Rate limiter constraints will be parsed from the
standard `keystone.conf` INI configuration file at startup. Handlers will
manually evaluate limits, and if a limit is exceeded, they will construct a
standardized `HTTP 429 Too Many Requests` response containing a `Retry-After`
header.

---

## 1. Configuration-Driven Limits

Rate limit thresholds (burst capacity and replenishment rates) MUST be defined
in the application's INI configuration file (e.g., `keystone.conf`). Hardcoding
limits in the application binary is strictly prohibited.

Operators must be able to disable specific governors independently to support
varying deployment topologies (e.g., disabling the application-level IP limit if
an upstream WAF or Load Balancer already enforces it).

### Configuration Schema (INI)

To remain compatible with OpenStack's `oslo.config` patterns, rate limits will
be grouped into distinct sections within the `keystone.conf` file:

```ini
[rate_limit_global_ip]
enabled = true
burst_size = 100
replenish_rate_per_second = 10

[rate_limit_user_auth]
# When false, the governor is not instantiated, and handlers bypass this check
enabled = false
burst_size = 5
replenish_rate_per_second = 1
```

### State Representation

To support disablement, the injected `AppState` will wrap the limiters in an
`Option`. If `enabled = false` is parsed from the INI config, the application
state stores `None` for that specific governor, and the handler safely ignores
the check.

If initialization fails (e.g., invalid parameter like
`replenish_rate_per_second = 0`) and the governor is marked `enabled = true`,
the application MUST fail to start. Silent fallback to no-limiting on
misconfiguration is a security regression.

```rust
pub type DefaultKeyedRateLimiter<K> = RateLimiter<K, DefaultKeyedStateStore<K>, governor::clock::MonotonicClock>;

pub struct RateLimitState {
    pub global_ip_limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
    pub user_auth_limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
}
```

---

## 2. Error Response Construction

When a rate limit is exceeded, the application must immediately halt request
processing and return an `HTTP 429 Too Many Requests` status code. To allow
clients to back off gracefully, the response MUST include specific HTTP headers
calculated from `governor`'s internal state.

### Required Headers

- **`Retry-After`:** Indicates how many seconds the client must wait before
  making a new request. This is extracted from `governor`'s `NotUntil` error
  payload, which calculates the difference between the next allowed cell and the
  current clock time. This is the only rate-limit-specific header required. No
  additional headers that might leak identifying information (e.g., the key that
  triggered the limit) should be included, to avoid user enumeration or PII
  exposure.

### Standardized Evaluation Method

To ensure uniform error formatting across all handlers, limit evaluation is
abstracted into a generic helper function.

```rust
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use governor::{clock::Clock, state::keyed::DefaultKeyedStateStore, RateLimiter};
use std::sync::Arc;

pub type DefaultKeyedRateLimiter<K> =
    RateLimiter<K, DefaultKeyedStateStore<K>, governor::clock::MonotonicClock>;

/// Evaluates a key against a given governor.
/// Constructs a standardized HTTP 429 Response if the limit is exceeded.
pub fn check_rate_limit<K: Clone>(
    limiter: &Arc<DefaultKeyedRateLimiter<K>>,
    key: &K,
) -> Result<(), Response> {
    limiter.check_key(key).map_err(|not_until| {
        let wait_secs = not_until
            .wait_time_from(governor::clock::MonotonicClock::default().now())
            .as_secs();

        let mut headers = HeaderMap::new();
        headers.insert(
            "Retry-After",
            HeaderValue::from_str(&wait_secs.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("60")),
        );

        (
            StatusCode::TOO_MANY_REQUESTS,
            headers,
            format!("Rate limit exceeded. Retry in {wait_secs}s"),
        )
            .into_response()
    })
}
```

---

## 3. Handler Execution Flow

Handlers execute limit checks based on their specific business logic, gracefully
handling cases where a governor has been disabled via the INI configuration.

For unauthenticated endpoints, per-IP rate limiting is the only throttle applied
before user lookup. Per-username rate limiting is applied **only after** the
user is confirmed to exist in the database, to prevent key-exhaustion bypass
attacks where the attacker crafts an infinite supply of novel usernames, each
with its own quota.

```rust
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(ip): ConnectInfo<SocketAddr>,
    Json(payload): Json<AuthPayload>,
) -> Result<Response, StatusCode> {
    // 1. IP Check (if enabled in keystone.conf)
    // IPv6 addresses are mapped to their /64 prefix before lookup.
    if let Some(ip_limiter) = &state.rate_limits.global_ip_limiter {
        let key = rate_limit_key_for_ip(ip.ip());
        if let Err(rejection_response) = check_rate_limit(ip_limiter, &key) {
            return Ok(rejection_response);
        }
    }

    // 2. Look up the user to verify existence BEFORE applying per-user limits.
    // Using the raw username as a rate-limit key before confirming existence
    // allows an attacker to craft novel usernames, each with independent quota.
    let user = state
        .identity_provider
        .get_user_by_name(&payload.username, &payload.domain)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    // NOTE: In production this maps only to NotFound; other errors propagate as 500.
    // The sample simplifies for brevity.

    // 3. User Account Check (if enabled in keystone.conf)
    // Applied only after user existence is confirmed.
    if let Some(user_limiter) = &state.rate_limits.user_auth_limiter {
        if let Err(rejection_response) = check_rate_limit(user_limiter, &user.id) {
            return Ok(rejection_response);
        }
    }

    // ... Proceed with heavy bcrypt/argon2 hashing and database verification ...
}
```

---

## 4. Security Invariants

Any code change violating the following is rejected at review:

1. **No Hardcoded Limits:** `burst_size` and `replenish_rate` MUST originate
   from the `keystone.conf` INI configuration state.
2. **Fail-Hard Initialization:** If a governor is configured with
   `enabled = true` but cannot be initialized (e.g., invalid parameters such as
   `replenish_rate_per_second = 0`), the application MUST fail to start. Silent
   fallback to no-limiting is a security regression.
3. **Response Uniformity:** The HTTP 429 response body and headers MUST be
   identical regardless of which governor tripped, to prevent additional
   disclosure channels beyond the status code itself. The 429 response MUST
   include a correctly calculated `Retry-After` header. No additional headers
   that expose the rate-limit key or any identifying information should be
   present, to prevent user enumeration via rate-limit probing.
4. **Pre-Hash Enforcement:** Rate limit checks for authentication endpoints MUST
   be executed _before_ any CPU-intensive operations (e.g., Argon2id/Bcrypt
   password verification) are triggered.
5. **Distinct Buckets:** Different operational contexts MUST use physically
   separate `RateLimiter` instances in the application state. Multiplexing
   different entity types into the same keyed store is prohibited.
6. **Monotonic Clock:** Rate limiters MUST use `governor::clock::MonotonicClock`
   to prevent NTP backward shifts from resetting quota windows.
7. **Key Normalization:** Any key derived from user input (e.g., username) MUST
   be normalized (lowercased, trailing `@` stripped, etc.) before being used as
   a rate-limit key. Normalization MUST match the canonicalization applied by
   the authentication logic.
8. **Post-Lookup User Throttle:** For unauthenticated endpoints, per-IP rate
   limiting is the primary throttle applied before any database lookup. Per-user
   rate limiting MUST only be applied after the user is confirmed to exist. This
   prevents key-exhaustion bypass attacks where an attacker crafts novel
   usernames, each with independent quota.

## Consequences

- **Per-node limits in scaled deployments:** `governor` uses in-memory
  `DefaultKeyedStateStore`. Each `keystone-rs` pod maintains its own counter. In
  a deployment with N instances behind a load balancer, the effective rate limit
  is N times the configured value. Operators should either configure limits
  per-node or migrate to a shared-state store (e.g., Redis-backed) for
  cluster-wide enforcement in the future.
- **IPv6 rate limiting via prefix aggregation:** IPv6 privacy extensions
  randomize source addresses per connection, making raw per-address limiting
  ineffective. Per-IP rate limiting defaults to aggregating IPv6 addresses by
  their `/64` network prefix, which corresponds to the subnet allocated to a
  single host's privacy extensions. Per-`/128` precision can be enabled by the
  operator but is not the default. IPv4 addresses are rate-limited per-`/32`.
- **Memory overhead and store eviction:** The keyed state store retains an entry
  per unique key. Under adversarial conditions (unique-key flooding), entries
  must be aggressively pruned. The store MUST:
  - Cap at a configurable maximum entry count (default: 10,000).
  - Be trimmed every 60 seconds via a background task.
  - When the cap is reached, new keys are dropped (fail-open: the request
    proceeds without per-key limiting, though the global IP limit still
    applies). This prevents memory exhaustion at the cost of allowing burst
    traffic under sustained key-flooding attacks.
- **Clock source:** `DefaultClock` uses `SystemTime`, which can be adjusted
  backward by NTP drift, resetting quota windows. Using `MonotonicClock`
  (required by Invariant 6) prevents this. The tradeoff is that `MonotonicClock`
  has no notion of wall-clock time, so quota replenishment cannot be aligned to
  calendar boundaries (e.g., daily resets). For security rate limiting this is
  desirable — an operator cannot accidentally reset attacker quotas by changing
  the system clock.
- **Key normalization:** Per-user rate-limit keys MUST be normalized before
  lookup. This means lowercasing, stripping trailing `@`, and any other
  canonicalization applied by the authentication logic. Without normalization,
  `admin`, `ADMIN`, and `admin@DEFAULT` would be treated as distinct keys, each
  with independent quotas. The normalization function should be a single shared
  utility to ensure consistency between the rate limiter and the authentication
  pipeline.
- **User enumeration trade-off:** Per-user rate limiting inherently enables user
  enumeration: if an attacker sends enough requests for `alice` to trip the
  limit (`429`), but requests for `alice_nonexistent` return `401`, the attacker
  learns that `alice` is a valid account. This is mitigated by this ADR's
  decision to apply per-user limiting only after user lookup (Invariant 8).
  Since the lookup already occurs, the enumeration risk is acceptable; the IP
  limit remains the primary throttle for unknown accounts.
- **HashMap timing side channel:** The `DefaultKeyedStateStore` performs
  hash-map lookups per key, which vary in execution time depending on whether
  the key exists (insert vs. update path). This timing difference can enable
  user enumeration independently of the 429 status code. This is inherent to the
  data structure and reinforces the decision to use IP-keyed limiting as the
  primary throttle for unauthenticated flows, where the timing channel is less
  actionable (IPs are not secrets).
- **Federation and application credential coverage:** Rate limiting on
  `POST /v3/auth/tokens` does not automatically cover federation endpoints
  (`OS-FEDERATION/identity_providers/{id}/protocols/{protocol}/authenticate`,
  `OS-FEDERATION/protocols/{protocol}/authenticate`), application credential
  flows, or token-based operations. These endpoints perform cryptographic
  verification and are CPU-intensive, making them denial-of-service targets. A
  follow-up ADR (tracking issue: TBD) will extend handler-level rate limiting to
  these endpoints with appropriate IP-based governance.
- **New dependency:** The `governor` crate must be added to the workspace
  `Cargo.toml`. It is actively maintained with no known security advisories.
- **Relationship with ADR 0010 (account lockout):** Rate limiting provides a
  first-layer defense by throttling all requests. ADR 0010 provides a second
  layer by locking the account after sustained failed authentication. Both
  mechanisms are independent and additive. A rate-limited request never reaches
  the lockout logic, reducing database writes for failed-auth counters.
