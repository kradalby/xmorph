# systemd integration

xmorph runs as a `rescue.target` unit: `systemctl isolate rescue.target`
tears down normal services and pivots into the configured rootfs. A
companion unit runs `xmorph build` on `multi-user.target` to populate its
build cache. Registry-image pivots do not reuse that cache and still need
registry access.

## NixOS module

```nix
{
  inputs.xmorph.url = "github:ananthb/xmorph";

  outputs = { self, nixpkgs, xmorph, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        xmorph.nixosModules.default
        {
          services.xmorph = {
            enable = true;
            package = xmorph.packages.x86_64-linux.default;

            images = [ "docker.io/library/alpine:latest" ];
            entrypoint = "/usr/local/bin/xmorph";
            command = [ "idle" ];

            ssh = {
              enable = true;
              authorizedKeys = "ssh-ed25519 AAAA... your-key-here";
            };

            tailscale = {
              enable = true;
              authKeyFile = "/run/secrets/tailscale-key";
            };

            warmupBuildCache = true; # default
          };
        }
      ];
    };
  };
}
```

The module installs two services:

- `xmorph-cache-warm.service` — runs on `multi-user.target` to populate the build cache
- `xmorph-pivot.service` — runs on `rescue.target` to pivot into the new rootfs

Trigger with `sudo systemctl isolate rescue.target`.

Replace the example public key with your own. The idle entrypoint keeps the
rescue system running without a terminal. SSH uses the configured credentials
over both the tailnet and host network; the Tailscale auth key only enrolls
the rescue node. For Headscale, set `tailscale.server` to its control URL.

For password authentication, set `services.xmorph.ssh.passwordFile` to a
quoted runtime path such as `"/run/secrets/xmorph-password"`. Provision that
file separately, owned by root with mode `0600`; do not use a Nix path
literal or `builtins.readFile`, which would copy the secret into the Nix
store. The wrapper passes only the filename; xmorph reads it before rootfs
preparation, stripping trailing LF newlines. The password crosses the pivot
through the private init configuration, never process arguments.
A missing or empty file aborts startup; the build-cache service
does not read it. The former inline `ssh.password` option is rejected
because it exposed the root password in a world-readable store script.

## Manual setup

Service files ship in the release tarball under
[`init/systemd/`](../init/systemd/):

- `xmorph-pivot.service` — pivots on `rescue.target`
- `xmorph-cache-warm.service` — pre-warms cache on boot

Install:

```sh
sudo cp init/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable xmorph-pivot.service xmorph-cache-warm.service
```

Edit the pivot service to configure images and Tailscale:

```sh
sudo systemctl edit xmorph-pivot.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/xmorph pivot --systemd-mode --force \
  --image alpine:latest \
  --entrypoint /usr/local/bin/xmorph --command idle \
  --ssh.authorized-keys "ssh-ed25519 AAAA... your-key-here" \
  --tailscale.authkey tskey-auth-xxxxx
```

`--systemd-mode` skips init coordination and process termination (systemd
already stopped services when entering `rescue.target`). The unit's
`CacheDirectory=xmorph` sets `CACHE_DIRECTORY`, so xmorph uses
`/var/cache/xmorph` automatically.

## Caching

`xmorph build` caches assembled images at the configured cache directory
(default `/var/cache/xmorph`; override with `--cache-dir` or
`CACHE_DIRECTORY`). The cache key is derived from the normalized layer
list — repeated `build` calls with the same layers can skip image pulls
and layer merges. `pivot` does not consult this cache: registry-image
pivots still require registry access even after the cache-warm unit succeeds.
