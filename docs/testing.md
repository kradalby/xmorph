# Testing

xmorph has three tiers of tests, matching how much of a real Linux kernel
each one needs.

## 1. Unit tests + lint (any OS)

```sh
nix run .#build      # gofmt + go vet (GOOS=linux) + go test
```

On Linux this runs `go test ./...`; on macOS it runs the pure-Go tests
natively and cross-compiles the rest. This is what the `build` CI job runs.

Tests that need root and mount namespaces (`internal/pivot`, and the
as-root tar-extraction cases in `internal/oci`) are guarded with
`if os.Geteuid() != 0 { t.Skip(...) }`, so they skip here rather than fail.

## 2. Integration tests on a real kernel (CI)

The pivot path — `pivot_root(2)`, mount ordering, tar extraction running as
root — can only be exercised against a real kernel with `CAP_SYS_ADMIN`.
The nix build sandbox can't do mounts, so the integration test binaries are
compiled by the `xmorphIntegrationTests` derivation and run inside a NixOS
VM test:

```sh
nix build -L .#checks.x86_64-linux.nixos-pivot   # pivot_root + extraction
nix flake check                                  # all checks + every VM test
```

The `integration` CI job runs `nixos-pivot` on every push and PR (GitHub's
Linux runners expose `/dev/kvm`). This is the project's real-kernel
regression coverage — notably it guards the mount-ordering invariant that
`/proc`, `/sys`, and `/dev` stay visible after the pivot.

## 3. Fast real-kernel iteration on macOS (developer option)

NixOS VM tests are the source of truth, but they're slow to iterate on. On
Apple Silicon you can run the same Linux tests directly against a real
kernel using [Apple `container`](https://github.com/apple/container), which
puts each container in its own lightweight VM.

One-time setup:

```sh
container system start
container system kernel set --recommended
```

Then run any package's tests as root with mount capabilities:

```sh
container run --rm --cap-add ALL \
  -v "$PWD:/src" \
  -v "$HOME/go/pkg/mod:/go/pkg/mod:ro" \
  -w /src \
  docker.io/library/golang:1.26 \
  sh -c 'GOFLAGS=-mod=mod GOPROXY=off go test -race ./...'
```

`--cap-add ALL` grants the `CAP_SYS_ADMIN` that `unshare`/`pivot_root`
require; mounting `$HOME/go/pkg/mod` read-only reuses your module cache so
the run is offline and fast. This is a convenience for local development —
CI relies on the NixOS VM test in tier 2, not on `container`.

## Headscale and post-pivot SSH

The `nixos-headscale` check uses the published Headscale `testkit` and
`testkit-peer` modules pinned in `flake.nix`, with Headscale's independent
nixpkgs/Go toolchain. The xmorph node uses the normal package and NixOS
service module. It performs a real `pivot_root` and execs `xmorph --init`;
SSH commands must read a marker that exists only in the new rootfs.
A DNS resolver on the control VM survives the pivot, using addresses derived
from the test network rather than hard-coded hosts entries. The kit supplies
HTTP control and self-signed, `InsecureForTests` DERP; no application TLS
certificate or production trust override is involved.

Run on Linux with access to `/dev/kvm` and Nix's `kvm` system feature:

```sh
nix build -L .#checks.x86_64-linux.nixos-headscale
nix run .#build
```

The VM check exercises:

- Malformed and option-restricted SSH keys abort before destructive lifecycle
  actions, even when a valid password accompanies malformed keys. The original
  OS remains usable and plain-key authentication succeeds after a valid pivot.
- A root-only runtime SSH password file, including shell-special characters;
  public module wrappers omit its contents. Missing or empty files abort
  startup, while the build-cache service works without that SSH credential.
- Invalid auth keys and unavailable control: the real service aborts before
  pivot, leaving the original OS usable; a valid key subsequently succeeds.
- A tagged rescue identity, default hostname/MagicDNS name and custom control
  URL; pre-pivot tsnet state is reopened after exec, with a single registered node and private
  state directory. The consumed init configuration is removed.
  Unit tests also cover custom hostnames and legacy arguments without a hostname.
- Actual IPv4/IPv6 SSH commands over a proven direct path and forced DERP,
  plus the kernel listener on the configured port. Password
  and public-key logins succeed; wrong passwords and unrelated keys fail
  with authentication errors, followed by a successful control operation.
- A live tag-based packet policy denying the outsider while the operator
  still executes commands. The outsider retains peer visibility and DERP
  ping access through a separate permitted port. Restoring policy restores
  the denied SSH operation.
- Control-server restart, direct application access during the outage, DERP
  recovery, a new online control connection, and unchanged node ID, node key
  and addresses.
- Control loss before init with saved tsnet state and cached network maps
  disabled. The production binary runs in a separate root directory and must
  start kernel SSH and its idle entrypoint despite the failed tailnet startup.

Scope follows the application: `postpivot.Run` calls `tsnet.Listen` through
`StartSSHServer`. Passwords and authorized keys authorize root shells; SSH
usernames are not mapped to local accounts. This is ordinary SSH, not
Tailscale SSH. The `ServeSSH`/`PostPivot` helpers using `ListenSSH` have no
production caller. There are no WhoIs calls, application capability grants,
Serve/Funnel, HTTPS certificate requests, subnet routes or exit nodes to test.
Tags come from the auth key; only hostname is interpreted from the legacy
`--tailscale.args` string, not `--advertise-tags` or `--ssh`.

The service requires root for mounts and pivot and has no unprivileged
sandbox; the test preserves those production privileges. Adding an
unprivileged tsnet service would not model this application. Persistence here
means the pre-authentication-to-init exec boundary and control restart, not
survival of reboot: the rescue root and its state live in tmpfs. Cloud-only
Tailscale SSH check-mode/SSO and public HTTPS issuance are not reproduced by
the local kit and are not exercised by the active application path.
