#!/usr/bin/env bash
# devstack plugin dispatcher for the rust Keystone ("key-rs") service.
#
# Standard devstack plugin phase hooks. python Keystone ("key") is left
# fully in charge of the base DB schema and initial bootstrap; this plugin
# only adds the rust binary on top and repoints Apache's /identity proxy
# at it once it is up, so it ends up serving traffic in python's place.
#
# See devstack/lib/keystone-rs for the actual install/configure/init/start
# functions, and doc/src/install.md ("Parallel installation with the
# python Keystone") for the deployment rationale.

KEYSTONE_RS_PLUGIN_DIR=$(dirname "${BASH_SOURCE[0]}")

source "$KEYSTONE_RS_PLUGIN_DIR/lib/keystone-rs"

if is_service_enabled key-rs; then
    # key-rs-opa is an internal implementation detail (the OPA sidecar this
    # plugin's run_process calls target), not a user-facing toggle - devstack's
    # run_process silently no-ops for any service name that isn't enabled, so
    # it must be enabled here rather than left for local.conf to opt into.
    enable_service key-rs-opa

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_keystone_rs
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_keystone_rs
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        init_keystone_rs
        start_keystone_rs
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_keystone_rs
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_keystone_rs
    fi
fi
