# Developer's guide

Running and testing the Keystone locally requires additional components. Easiest
way to achieve it is to use the docker-compose or the `skaffold` to deploy
components into the small Kubernetes cluster.

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
local docker. When not available the registry can be easily [deployed
locally](https://www.docker.com/blog/how-to-use-your-own-registry-2/).

Skaffold can be invoked with the following command to build and push images,
deploy kubernetes manifests and watch for the changes for reload:

```console

skaffold dev --default-repo localhost:5000

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
