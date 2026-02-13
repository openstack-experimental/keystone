# Distributed storage for Keystone

Distributed storage backend for the OpenStack Keystone backed by Raft consensus
protocol and the Fjall KV database.

Central RDBMS is preventing OpenStack Keystone to be deployed as a flexible and
distributed system. Major IAM systems are built with the Raft based storage to
make the them fully distributed and highly available. This project aims to provide
such a storage that is on the one side has a guaranteed consistency between
multiple instances, while on the other side rely on the KV database that is
being modified under the Raft control and being readable by every instance at
the very high speed.
