# Local devstack-full replica

Local, throwaway-VM equivalent of the `devstack-full` CI job
(`.github/workflows/devstack.yml`). Runs the full single-node stack -
Nova/Cinder/Glance/Neutron(OVN)/SPIRE on top of rust Keystone - so you can
iterate on SPIRE integration / service-auth changes without waiting on CI.

`run.sh` is the extracted job body (steps 337-488 of the workflow). Both CI
and this script should stay thin wrappers around the same shape so fixes
made locally land in CI too - if you change one, check the other still
matches.

## What it needs

- Ubuntu 24.04 (noble), systemd. devstack drives services via
  `devstack@*` systemd units.
- ~4 vCPU / 8-16 GB RAM / 60-100 GB disk. mysql + rabbit + OVN +
  nova/cinder/glance + 4 spiffe-helpers + tempest is heavier than a
  keystone-only devstack.
- **Nested KVM**, for `n-cpu` and the cirros boot/delete smoke test:
  nova-compute runs libvirt inside what is itself a VM. GitHub's
  `ubuntu-24.04` runners are themselves VMs with nested KVM enabled and
  this passes there, so it's proven to work in this exact shape.
- A real branch checked out (not detached HEAD) is *not* required locally -
  `run.sh` bypasses devstack's git clone for the key-rs/SPIRE plugins
  entirely (see "How local state gets in" below).

Run `run.sh` only inside a disposable VM/host you don't care about - it
installs system packages/services and is destructive to `/opt/stack`.

## One-time VM setup (Option A: virt-install + host-passthrough)

On the host (needs libvirt/qemu-kvm):

```sh
virt-install \
  --name devstack-full \
  --vcpus 4 --memory 16384 \
  --disk size=100 \
  --cpu host-passthrough \
  --network network=default \
  --os-variant ubuntu24.04 \
  --cloud-init user-data=cloud-init.yaml \
  --location <path-or-url-to-ubuntu-24.04-cloud-image>
```

Seed `cloud-init.yaml` (or equivalent NoCloud config) to install
prerequisites and enable nesting:

```yaml
#cloud-config
package_update: true
packages:
  - git
  - curl
  - rsync
  - qemu-kvm
  - libvirt-daemon-system
users:
  - default
  - name: ubuntu
    groups: [kvm, libvirt]
    sudo: ALL=(ALL) NOPASSWD:ALL
```

Verify nesting actually works *inside* the guest before doing anything
else - if this fails, `n-cpu` will fail too, much later and much more
confusingly:

```sh
test -e /dev/kvm && egrep -c '(vmx|svm)' /proc/cpuinfo
```

Put the VM on NAT or a dedicated libvirt network, not your workstation's
LAN bridge - OVN/flat bridges inside the guest will otherwise fight host
addressing.

## Getting the repo in

You don't need to push anywhere. Either:

- **virtiofs/9p mount** the keystone-rs worktree into the guest (fastest
  iteration - edits on the host show up immediately), or
- **`git clone` the worktree itself** as a local-path origin inside the
  guest (`git clone /path/to/worktree /home/ubuntu/keystone-rs` from a host
  mount, or `rsync` it in once and `git pull` from a mount for updates).

Either way, `run.sh --workspace <path>` just needs a working tree it can
read and rsync from - it doesn't care how that tree got onto the VM.

## How local state gets in (no push, no commit)

The CI job points devstack's `enable_plugin key-rs file://<workspace> <ref>`
at the checked-out branch, which only sees *committed* state. `run.sh`
does something different: it `rsync`s your live working tree (staged,
unstaged, untracked - everything except `.git`/`target`) straight into
`/opt/stack/key-rs` before `stack.sh` runs.

devstack's `git_clone()` (functions-common) is a no-op whenever its
destination directory already exists and `RECLONE` isn't set - so with
`/opt/stack/key-rs` pre-populated, devstack never clones or fetches
anything for that plugin; it just uses what's there. Same for the SPIRE
plugin at `/opt/stack/spire`. Net effect: no commit and no push required
to test uncommitted local changes, and re-running the script re-syncs +
re-stacks with whatever the working tree looks like *right now*.

## Running it

Inside the guest, with a prebuilt release binary (mirrors the CI
artifact - skips a redundant `cargo build --release` inside the run):

```sh
cargo build --release -p openstack-keystone -p openstack-keystone-cli-manage   # on the host, or in the guest
tools/devstack-full/run.sh --workspace /path/to/keystone-rs --bin-dir /path/to/target/release
```

Or let it build for you:

```sh
tools/devstack-full/run.sh --workspace /path/to/keystone-rs
```

Useful flags:

- `--skip-build` - reuse an existing `target/release` under `--workspace`
  without rebuilding.
- `--skip-smoke` - skip the cirros boot/delete smoke test (still runs
  everything else - service health, SPIRE checks).
- `--skip-verify` - stop right after `stack.sh`, skip all verification.
- `--restack` - run devstack's own `unstack.sh` + `clean.sh` before
  re-stacking, for when you want a truly clean run rather than devstack's
  normal incremental re-stack.

See `run.sh --help` for the full list.

## Iterating

Keep the VM around between runs. A typical loop:

1. Edit code on the host (or in the guest, if you cloned there directly).
2. `cargo build --release` if binaries changed.
3. Re-run `tools/devstack-full/run.sh --workspace ... --bin-dir ...` -
   re-syncs the plugin dirs and re-stacks.

Cold run (fresh VM): ~40-60 min. Warm re-runs: ~20-30 min.

## Caveats

- Nested virtualization makes the cirros smoke test noticeably slower than
  bare metal; use `--skip-smoke` for faster inner-loop iteration and drop
  it for the occasional full validation pass.
- GitHub-runner-specific package purges (stock MySQL, `esl-erlang`, the
  `/etc/hosts` sed, stray postgres) are deliberately **not** in `run.sh` -
  a clean noble image doesn't have any of those conflicts to begin with.
- Day-to-day keystone-rs/SPIRE-plugin changes are already covered by
  `cargo test` and the lighter `devstack` CI job (keystone-only, no KVM
  needed). Reserve this full nested-VM run for pre-PR validation, not
  every edit.
