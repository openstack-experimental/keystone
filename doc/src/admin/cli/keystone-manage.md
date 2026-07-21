# `keystone-manage` administration command

`keystone-manage` performs administrative operations using the configured
database, admin interface, key repositories, or distributed-storage endpoint.

```console
keystone-manage --config /etc/keystone/keystone.conf <command>
```

| Command | Purpose |
| --- | --- |
| `bootstrap` | Create or update the initial domain, project, user, roles, assignments, and optional catalog endpoints. |
| `catalog service` | Create, list, show, update, or delete catalog services. |
| `catalog endpoint` | Create, list, show, update, or delete catalog endpoints. |
| `credential setup|migrate|rotate` | Manage credential-encryption keys and re-encryption. |
| `db sync|up|down|status|fresh|refresh|reset` | Manage SQL schema and migrations. Destructive database commands require an explicit operational review. |
| `oauth2 ensure-signing-key` | Provision a missing domain signing key. |
| `oauth2 rotate-signing-key|confirm-rotate-signing-key` | Perform normal signing-key rotation. |
| `oauth2 list-local-emergency-candidates|reconcile-local-emergency-key` | Inspect and reconcile quorum-loss candidates. |
| `storage init|join|list-peers|promote|demote|remove-peer` | Manage Raft membership. |
| `storage backup|restore|metrics|clear-quarantine` | Operate and recover distributed storage. |
| `storage rotate-dek|confirm-rotate-dek` | Rotate distributed-encryption keys. |
| `storage list-dek-local-emergency-candidates|reconcile-dek-local-emergency` | Inspect and reconcile local emergency DEK candidates. |
| `token setup|rotate` | Initialize or rotate the Fernet token repository. |

Use `<command> --help` before execution. Follow the linked administrator runbook
for [Fernet tokens](../tokens/fernet.md),
[OAuth2/OIDC](../features/oauth2.md), or
[distributed storage](../storage/distributed.md); command help describes
syntax, while the runbook describes ordering and safety constraints.
