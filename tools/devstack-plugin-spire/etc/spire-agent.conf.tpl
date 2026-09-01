agent {
    data_dir = "@SPIRE_DATA_DIR@"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "@SPIRE_SERVER_BIND_PORT@"
    socket_path = "@SPIRE_AGENT_SOCKET@"
    trust_domain = "@SPIRE_TRUST_DOMAIN@"
    # Single-node devstack bootstrap only, matching tools/start-spire.sh -
    # the agent trusts the server's cert on first connect instead of
    # verifying it against a pre-distributed bundle.
    insecure_bootstrap = true
}

plugins {
    KeyManager "memory" {
        plugin_data {}
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
