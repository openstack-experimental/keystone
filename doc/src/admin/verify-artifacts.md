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

## Container image properties

- The image runs as the unprivileged user `keystone` (uid and gid `65532`).
  Orchestrators should keep `runAsNonRoot: true` and the same `fsGroup`.
- Keystone writes only to paths you mount: configuration and key directories,
  the log directory, the admin socket directory, the storage `path`, and
  `/tmp`. Run it with a read-only root filesystem and all capabilities
  dropped, as the reference manifests in `tools/k8s/keystone` do.
- The base images are pinned by digest in `Dockerfile` and `Dockerfile.opa`;
  Dependabot proposes updates.
