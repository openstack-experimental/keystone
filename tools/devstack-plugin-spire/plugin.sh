#!/usr/bin/env bash
# devstack plugin dispatcher for SPIRE (SPIFFE workload identity).
#
# Standard devstack plugin phase hooks, mirroring devstack/plugin.sh's
# shape. This plugin is independent of the "key-rs" plugin in devstack/ -
# it only stands up a SPIRE server + agent, distributes the trust bundle,
# and pre-registers the well-known SPIFFE identities later phases
# (keystone-rs's internal SPIFFE mTLS listener, the vendor-data JWT API)
# authenticate against. See doc/plans/spire-integration.md, Phase 1.
#
# See lib/spire for the actual install/configure/init/start functions.

SPIRE_PLUGIN_DIR=$(dirname "${BASH_SOURCE[0]}")

source "$SPIRE_PLUGIN_DIR/lib/spire"

if is_service_enabled spire; then
    # spire-server and spire-agent are the internal run_process units the
    # start/stop functions target, not user-facing toggles - devstack's
    # run_process silently no-ops for any service name that isn't enabled,
    # so they must be enabled here (mirroring key-rs's key-rs-opa). "spire"
    # remains the single toggle operators use in local.conf.
    enable_service spire-server spire-agent

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_spire
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_spire
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        init_spire
        start_spire
    fi

    if [[ "$1" == "unstack" ]]; then
        stop_spire
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_spire
    fi
fi
