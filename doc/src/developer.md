# Contributor Documentation

Running and testing the Keystone locally requires additional components (DB,
OpenPolicyAgent, etc). Easiest way to achieve it is to use the docker-compose or
the `skaffold` to deploy components into the small Kubernetes cluster.

## Skaffold

When a kubernetes is available for the local development and testing the
[skaffold](https://skaffold.dev/) can be used to deploy Keystone, OPA, database
and the python keystone together. This is very helpful for being able to test
the compatibility between Keystone implementations and running the API tests
that require the system to be up and running.

It is necessary to have any sort of the image registry running that can be
accessed by the K8 to pull images from. It depends heavily on the concrete K8
implementation since some may come with the built-in registry that the local
docker can push directly to or that the K8 accesses the images directly from the
local docker. When not available the registry can be easily
[deployed locally](https://www.docker.com/blog/how-to-use-your-own-registry-2/).

Skaffold can be invoked with the following command to build and push images,
deploy kubernetes manifests and watch for the changes for reload:

```console

skaffold dev --default-repo localhost:5000 -p local

```

It might be useful to add `--cleanup=false` flag to the above command to prevent
skaffold from tearing down all resources when the process is stopped.

Currently the manifests are built to expose the Kestone within the K8 cluster
under: `http://keystone.local` (with certain routes pointing to the python
version and others to the rust), `http://keystone-rs.local` (rust version) and
`http://keystone-py.local` (the python version correspondingly). Depending on
the how the K8 is being deployed and access the Keystone may be directly
accessible from the localhost when i.e. the routes are added in the `/etc/hosts`
file. The manifests are not currently designed to be used for production
deployment.

With the keystone deployed in the Kubernetes running API tests can be performed
with the following command:

```console

KEYSTONE_URL=http://keystone-rs.local cargo nextest run --test api

```

The same can be also performed with the `skaffold` itself with test suites
packaged into containers and deployed into the Kubernetes. This is very helpful
to do a real functional/integration test for the Kubernetes based authentication
that requires a fully functional cluster. The same is true for the federation
tests where it is necessary to have a running IdP that can be integrated with
the Keystone.

```console

# Build all container images saving the metadata into the `build.artifacts` file
skaffold build --profile local --default-repo localhost:5000 --output-file build.artifacts

# Deploy Keystone with database and OPA to K8s
skaffold deploy -a build.artifacts

# Run the tests inside the K8s
skaffold verify -a build.artifacts
```

## OpenStackClient (OSC)

Deploying Keystone in the Kubernetes makes it also possible to verify the
authentication flows using the `osc` that brings client support for all
authentication methods.

Depending on the Kubernetes cluster the address under which Keystone is
reachable may differ. As described above corresponding names should be added
into the `/etc/hosts` file.

```yaml

clouds:
  keystone-skaff:
    auth:
      auth_url: http://keystone-rs.local
      username: admin
      password: password
      user_domain_name: Default
      project_domain_name: Default
      project_name: admin
      domain_id: default
```

This way authentication using the passkey can be verified manually.
