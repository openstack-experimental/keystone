#!/usr/bin/env bash
# Custom skaffold builder used by the `github-ci` profile (skaffold.yaml).
#
# Builds tools/Dockerfile.skaffold with `docker buildx build` so the layers
# (in particular the cargo-chef `cook` layer holding the compiled
# dependencies) can be imported from / exported to a remote registry cache
# between CI runs. Skaffold's own docker builder has `cacheFrom` but no
# `--cache-to`, hence this wrapper.
#
# Skaffold provides: IMAGE (full name:tag), PUSH_IMAGE ("true"/"false"),
# BUILD_CONTEXT.
#
# Optional environment:
#   BUILDCACHE_REF   registry reference used as cache (e.g.
#                    ghcr.io/<owner>/<repo>-buildcache:skaffold). Without it
#                    the build runs uncached.
#   BUILDCACHE_PUSH  "true" to also export the cache (needs write access to
#                    BUILDCACHE_REF; unset for fork pull requests).
set -euo pipefail

: "${IMAGE:?IMAGE is set by skaffold}"
CONTEXT="${BUILD_CONTEXT:-.}"

base_args=(--file "${CONTEXT}/tools/Dockerfile.skaffold" --tag "${IMAGE}" --load)
args=("${base_args[@]}")

if [[ -n "${BUILDCACHE_REF:-}" ]]; then
  args+=(--cache-from "type=registry,ref=${BUILDCACHE_REF}")
  if [[ "${BUILDCACHE_PUSH:-}" == "true" ]]; then
    # mode=max also exports the intermediate stages (cook layer).
    args+=(--cache-to "type=registry,ref=${BUILDCACHE_REF},mode=max,image-manifest=true,oci-mediatypes=true,ignore-error=true")
  fi
fi

# Pulling the large cached layers from the registry can fail transiently
# (e.g. "short read ... unexpected EOF"). Retry once with the cache, then
# fall back to an uncached build so a flaky cache never fails the job.
if ! docker buildx build "${args[@]}" "${CONTEXT}"; then
  echo "buildx build failed, retrying" >&2
  if ! docker buildx build "${args[@]}" "${CONTEXT}"; then
    echo "retry failed, building without the registry cache" >&2
    docker buildx build "${base_args[@]}" "${CONTEXT}"
  fi
fi

# The image was loaded into the local docker daemon; skaffold expects it to
# be pushed when PUSH_IMAGE is true (default-repo is the local registry).
if [[ "${PUSH_IMAGE:-false}" == "true" ]]; then
  docker push "${IMAGE}"
fi
