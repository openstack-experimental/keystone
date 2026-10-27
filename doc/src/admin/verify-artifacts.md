# Verifying release artifacts

Release binaries and container images carry GitHub build attestations. Verify
them before deploying, with the [GitHub CLI](https://cli.github.com/):

```console
# Container image (use the digest you deploy, not a mutable tag)
$ gh attestation verify \
    oci://ghcr.io/openstack-experimental/keystone@sha256:<digest> \
    --repo openstack-experimental/keystone

# Release archive downloaded from the GitHub release
$ gh attestation verify keystone-<target>.tar.xz \
    --repo openstack-experimental/keystone
```

The command fails if the artifact was not built by this repository's release
workflows, or if it was modified after the build. Pin the verified digest in
your manifests (`image: ghcr.io/openstack-experimental/keystone@sha256:…`)
instead of a tag.

The OPA policy bundle (`ghcr.io/openstack-experimental/keystone/opa-bundle`)
is signed separately with keyless `cosign` signatures; verify it with
`cosign verify` against the bundle digest.

## SBOM and VEX

Each GitHub release carries a CycloneDX 1.5 SBOM per shipped binary
(`keystone_bin.cdx.json`, `keystone-manage_bin.cdx.json`) and the OpenVEX
document `keystone.openvex.json`. They are attested like the archives:

```console
$ gh attestation verify keystone_bin.cdx.json \
    --repo openstack-experimental/keystone
```

The VEX document states, for each advisory the project has chosen to ignore,
whether Keystone is affected and what an operator should do; see
[VEX statements](../contributor/vex.md). The container images additionally carry
a BuildKit SPDX SBOM attestation covering the operating-system packages:

```console
$ docker buildx imagetools inspect \
    ghcr.io/openstack-experimental/keystone@sha256:<digest> \
    --format '{{ json .SBOM }}'
```

## Verifying the OPA policy bundle at load time

The `opa-bundle` image is signed with keyless `cosign` by the policy
workflow. The production overlay serves the policies baked into the attested
`keystone-opa` image. To serve the signed bundle instead, add the
`opa-bundle-component` to your overlay:

```yaml
components:
  - ../opa-bundle-component
```

An init container (`keystone-bundle-verify`) resolves the bundle tag to a
digest, runs `cosign verify` against this repository's GitHub Actions
identity, and writes an OPA config pinned to the verified digest. OPA starts
only after that succeeds, so a bad signature leaves the pod in `Init:Error`.
The pod needs egress to `ghcr.io` and the Sigstore endpoints. The standalone
`tools/opa_config.yaml` ships with an all-zero digest that never resolves: run
`tools/verify_and_pin_opa_bundle.sh --repo <owner/repo> --tag <tag>` to pin it.

## Container image properties

- The image runs as the unprivileged user `keystone` (uid and gid `65532`).
  Orchestrators should keep `runAsNonRoot: true` and the same `fsGroup`.
- Keystone writes only to paths you mount: configuration and key directories,
  the log directory, the admin socket directory, the storage `path`, and
  `/tmp`. Run it with a read-only root filesystem and all capabilities
  dropped, as the reference manifests in `tools/k8s/keystone` do.
- The base images are pinned by digest in `Dockerfile` and `Dockerfile.opa`;
  Dependabot proposes updates.
