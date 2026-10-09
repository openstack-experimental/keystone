# Local Development

Running the complete service locally requires a database and Open Policy Agent
(OPA). Docker Compose and Skaffold provide those dependencies.

## Prerequisites

- Stable Rust toolchain
- `pre-commit`
- `cargo-nextest` for integration profiles
- SPIRE for live API tests
- Optional Skaffold and a Kubernetes cluster for the full deployment
- Optional `k3s`, a local registry at `localhost:5000`, CloudNativePG, the SPIRE
  controller manager and a SPIRE trust domain of `example.org` for the
  single-voter Raft KEK overlay smoke tests

Install repository hooks after cloning:

```console
pre-commit install
```

## Local Build

Always name the crate for crate-specific Cargo commands:

```console
cargo build -p openstack-keystone
cargo check -p openstack-keystone --message-format=short
cargo test -p openstack-keystone
```

## Skaffold

The Skaffold configuration can deploy Keystone-NG, Python Keystone, OPA, the
database, and supporting identity providers to a local Kubernetes cluster:

```console
skaffold dev --default-repo localhost:5000 -p local
```

Use `--cleanup=false` when resources must remain after Skaffold exits. The
repository configuration exposes mixed, Rust-only, and Python-only endpoints;
consult `skaffold.yaml` for the current modules and profiles.

The Skaffold deployment (`tools/k8s/keystone/overlays/skaffold`) is a
development setup: it runs the Raft storage in dev mode with an environment
KEK and keeps nothing across pod restarts. Do not use it as a deployment
template; the production reference is `tools/k8s/keystone/overlays/production`,
described in the distributed storage
[Kubernetes reference deployment](../admin/storage/distributed.md#kubernetes-reference-deployment).

## Raft KEK overlays on k3s

`tools/k8s/keystone/overlays/k3s-test` contains throwaway, single-voter overlays
for smoke-testing the `pkcs11` and `tpm` Raft KEK providers on a local k3s
node. They are not quorum deployments. The full reference, including the host
TPM limitation, is the
[Single-voter k3s smoke test](../admin/storage/distributed.md#single-voter-k3s-smoke-test)
section of the distributed storage documentation.

The `skaffold-k3s-test.yaml` file, with the `pkcs11` or `tpm` profile, builds
and pushes the required images to `localhost:5000`, then deploys the matching
overlay. Use the same `--tag raft-test` value that the overlays expect.
CloudNativePG and the SPIRE controller manager must already be installed
(the main `keystone` module installs both).

### PKCS#11 overlay

The PKCS#11 overlay uses SoftHSM2. It initialises the token and generates the
AES-256 KEK automatically on the StatefulSet volume. The Skaffold module
creates the `keystone-pkcs11-pin` Secret before deploying:

```console
skaffold run -f skaffold-k3s-test.yaml \
  -p pkcs11 --default-repo localhost:5000 --tag raft-test --cleanup=false
kubectl -n keystone-raft-test get pods -w
```

### TPM overlay

The TPM overlay runs a `swtpm` sidecar in the pod. First provision the
sidecar's state and the KEK context files on the k3s host:

```console
sudo mkdir -p /var/lib/keystone-raft-test/swtpm
sudo chown 65532:65532 /var/lib/keystone-raft-test/swtpm

swtpm socket \
  --tpmstate dir=/var/lib/keystone-raft-test/swtpm \
  --ctrl type=tcp,port=2352 --server type=tcp,port=2351 \
  --tpm2 --flags not-need-init &
SWTPM_PID=$!

export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2351"
tpm2_startup -c
TPM_KEK_TCTI="$TPM2TOOLS_TCTI" \
  TPM_KEK_CONTEXT_FILE=/tmp/keystone-tpm-kek.ctx \
  cargo run -p openstack-keystone-storage-crypto-tpm --example tpm_kek_demo

kill "$SWTPM_PID"
sudo rm -f /var/lib/keystone-raft-test/swtpm/.lock
```

If the TPM reports DA lockout, delete `/var/lib/keystone-raft-test/swtpm/*`
and repeat the provisioning steps.

Then deploy the overlay. The Skaffold module creates the `keystone-tpm-kek`
Secret from `/tmp/keystone-tpm-kek.ctx` and
`/tmp/keystone-tpm-kek.ctx.hmac`:

```console
skaffold run -f skaffold-k3s-test.yaml \
  -p tpm --default-repo localhost:5000 --tag raft-test --cleanup=false
kubectl -n keystone-raft-test get pods -w
```

When testing API flows, port-forward the service and authenticate as the
bootstrapped `admin` user against project `admin`:

```console
kubectl -n keystone-raft-test port-forward svc/keystone-rs 18080:8080
```

The `k3s-raft-pkcs11` job in `.github/workflows/functional.yml` runs the PKCS#11
overlay in CI when the storage crates or the Kubernetes overlays change.
`tools/k3s-raft-smoke.sh` is the check it runs and can be used locally against
a deployed overlay: it authenticates as `admin`, restarts the pod and verifies
that the earlier token is still valid.

Tear down either variant with:

```console
skaffold delete -f skaffold-k3s-test.yaml \
  -p pkcs11 --default-repo localhost:5000
skaffold delete -f skaffold-k3s-test.yaml \
  -p tpm --default-repo localhost:5000
```

## OpenStackClient

Point an OpenStackClient cloud entry at the deployment's Rust or mixed endpoint
and provide the configured domain, project, username, and password. Use the
generated [OpenAPI reference](../swagger-ui.html) when testing Keystone-NG-only
v4 routes that OSC does not expose.

## Submission

Run the relevant tests, `pre-commit run --all-files`, and
`git diff --check`. Commits use Conventional Commits and must include the DCO
sign-off with `git commit -s`.
