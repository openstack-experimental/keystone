# Fernet Tokens

Fernet is the default token provider. Keystone-NG uses the same
integer-indexed key repository model as Python Keystone so that both services
can issue and validate tokens when they share an identical key set.

Fernet tokens are bearer credentials. Protect the key repository as secret
material and use TLS for every client-facing connection.

## Configuration

```ini
[token]
provider = fernet
expiration = 3600

[fernet_tokens]
key_repository = /etc/keystone/fernet-keys/
max_active_keys = 3
insecure_allow_null_key = false
```

`expiration` is the token lifetime in seconds. `key_repository` defaults to
`/etc/keystone/fernet-keys/`, and `max_active_keys` defaults to `3`.

`insecure_allow_null_key` is a migration-only escape hatch. Keep it `false` in
production. Keystone refuses to start when the repository contains the
well-known Null Key unless this option is explicitly enabled.

## Key Repository

Each key is stored in a file named with an integer:

- `0` is the staged key for the next rotation.
- The highest positive index is the primary key used to encrypt new tokens.
- Lower positive indexes remain available to decrypt tokens issued before a
  rotation.

`max_active_keys` includes the staged key. With the default value of `3`, the
repository retains `0` and up to two positive-index keys. Choose the rotation
schedule and retained-key count so a key is not pruned while tokens encrypted
with it can still be valid.

All Rust and Python Keystone nodes must use the same complete file set. Do not
initialize or rotate separate repositories independently on different nodes.
Use a shared secret volume or distribute the complete repository to every node
before a node begins issuing tokens with a new primary key.

## Initial Setup

Run setup once against the deployment's canonical repository before serving
token requests:

```console
keystone-manage --config /etc/keystone/keystone.conf token setup
```

The command creates key `0`. It overwrites an existing staged key, so do not
rerun it as a routine startup action. Run the command as the account that should
own the repository; generated key files are written with owner-only
permissions.

Verify file names, ownership, and modes without printing key contents:

```console
find /etc/keystone/fernet-keys -maxdepth 1 -type f -printf '%f\n' | sort -n
stat -c '%a %U:%G %n' /etc/keystone/fernet-keys/*
```

## Rotation

Rotate the canonical repository with:

```console
keystone-manage --config /etc/keystone/keystone.conf token rotate
```

Rotation performs three operations:

1. Promotes staged key `0` to the next positive primary index.
2. Generates a new staged key at index `0`.
3. Removes the oldest positive-index keys beyond `max_active_keys`.

Tokens are not re-encrypted. They remain usable only while the key that issued
them is retained. The command does not check token lifetime before pruning, so
operators must make the retention window longer than the maximum lifetime of
tokens that may still be accepted.

The running Rust service watches the repository for changes and also polls it
every 30 seconds. A valid rotation is loaded without restarting Keystone. If a
reload fails, the service logs the failure and continues using the previous
valid in-memory key set.

## Multi-Node Rotation

For a shared repository, run the rotation command once. Every Rust process
watching that repository reloads the resulting key set.

For repositories copied to each node:

1. Back up the current canonical repository securely.
2. Rotate one canonical copy.
3. Distribute the complete new file set to every Rust and Python node.
4. Confirm every node has the same indexes before returning normal traffic.

Do not rotate one node and leave it issuing tokens before the other nodes have
the new primary key; those nodes will be unable to validate its tokens.

## Troubleshooting

**Keystone reports that no usable Fernet keys were found**

- Confirm `key_repository` points to the mounted directory.
- Confirm setup has been run and the service account can read the key files.

**Tokens fail validation after rotation**

- Compare the key file indexes on every node.
- Check whether `max_active_keys` pruned a key before its tokens expired.
- Check the service log for a failed repository reload.

**Keystone refuses to start because of the Null Key**

- Replace the Null Key through a controlled repository migration.
- Do not enable `insecure_allow_null_key` as a production workaround.
