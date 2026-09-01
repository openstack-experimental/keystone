server {
    bind_address = "127.0.0.1"
    bind_port = "@SPIRE_SERVER_BIND_PORT@"
    trust_domain = "@SPIRE_TRUST_DOMAIN@"
    data_dir = "@SPIRE_DATA_DIR@"
    log_level = "INFO"
    socket_path = "@SPIRE_SERVER_SOCKET@"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "@SPIRE_DATA_DIR@/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "@SPIRE_DATA_DIR@/keys.json"
        }
    }

    # join_token is single-node/insecure-bootstrap only, matching
    # tools/start-spire.sh's CI harness. Production deployments would use
    # x509pop or another attestor that actually proves node identity - see
    # doc/plans/spire-integration.md Phase 1 "Per-host nova-compute
    # registration" for why this matters for the nova-compute entries this
    # plugin registers below.
    NodeAttestor "join_token" {
        plugin_data {}
    }
}
