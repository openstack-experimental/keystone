# Configuration Reference

Keystone configuration uses INI sections and supports three ordered sources:
the file passed to `--config`, an optional `KEYSTONE_SITE_VARS_FILE`, and `OS_`
environment variables. Environment names use `__` between section and option,
for example `OS_DATABASE__CONNECTION`.

- [Configuration options](options.md) inventories the public sections and
  option names parsed by `crates/config`.
- [Administrator configuration](../admin/configuration.md) provides deployment
  guidance and listener security requirements.
- Feature administrator guides explain valid combinations and operational
  consequences.

Secret-valued options may also have file/content forms in their owning section.
Never place secret values in documentation, logs, or command output.
