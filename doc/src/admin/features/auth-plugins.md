# Dynamic Authentication Plugin Operations

Dynamic authentication plugins are WebAssembly modules loaded from paths named
by `[auth_plugins]`. Each plugin has a corresponding `[auth_plugin.<name>]`
section containing its path, pinned SHA-256 digest, operating mode,
capabilities, network allowlist, and resource limits.

Before deployment:

1. Build and review the module from a trusted source.
2. Pin its SHA-256 digest.
3. Grant only the required host capabilities and outbound hosts.
4. Configure time, fuel, memory, concurrency, and invocation-rate limits.
5. Restart Keystone and verify load status without logging secrets.

When replacing a module, update `valid_since` so tokens issued through the old
version can be rejected according to deployment policy. Use the administrative
identity-link and revoke-all APIs for controlled linking and compromise
response.

See [Authentication plugin development](../../contributor/auth-plugins.md) for
the guest contract, host functions, and testing workflow.
