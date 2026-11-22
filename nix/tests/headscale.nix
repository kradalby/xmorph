{ pkgs, lib, xmorph-package, xmorph-module, headscale }:

let
  keys = import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs;
  policy = sources: pkgs.writeText "xmorph-policy.json" (builtins.toJSON {
    tagOwners."tag:rescue" = [ "operator@" ];
    acls = [
      { action = "accept"; src = sources; dst = [ "tag:rescue:2222" ]; }
      # Keep the peer visible so SSH denial exercises inbound packet filtering.
      { action = "accept"; src = [ "outsider@" ]; dst = [ "tag:rescue:1" ]; }
    ];
  });
  allowed = policy [ "operator@" "outsider@" ];
  restricted = policy [ "operator@" ];
  peer = {
    imports = [ headscale.nixosModules.testkit-peer ];
    environment.systemPackages = [ pkgs.openssh pkgs.jq ];
  };

  # The resolver survives on another VM; no pinned VLAN addresses or hosts file.
  rootfs = dns: pkgs.runCommand "xmorph-headscale-rootfs" {
    nativeBuildInputs = [ pkgs.gnutar pkgs.gzip ];
  } ''
    mkdir -p rootfs/{bin,usr/local/bin,etc,dev,proc,sys,tmp,var/run}
    cp ${pkgs.pkgsStatic.busybox}/bin/busybox rootfs/bin/
    for cmd in sh cat sleep test; do
      ln -s busybox rootfs/bin/$cmd
    done
    echo 'nameserver ${dns}' > rootfs/etc/resolv.conf
    echo pivoted-root > rootfs/etc/pivot-marker
    tar czf $out -C rootfs .
  '';
in
pkgs.testers.nixosTest {
  name = "xmorph-headscale";

  nodes = {
    headscale = { config, ... }: {
      imports = [ headscale.nixosModules.testkit ];
      environment.systemPackages = [ pkgs.jq ];
      services.dnsmasq = {
        enable = true;
        settings = {
          no-resolv = true;
          address = "/headscale/${config.networking.primaryIPAddress}";
        };
      };
      networking.firewall.allowedUDPPorts = [ 53 ];
    };
    direct = peer;
    relay = {
      imports = [ peer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
    target = { nodes, ... }: {
      imports = [ xmorph-module ];
      services.xmorph = {
        enable = true;
        package = xmorph-package;
        images = [ ];
        rootfs = [ (toString (rootfs nodes.headscale.networking.primaryIPAddress)) ];
        warmupBuildCache = false;
        entrypoint = "/usr/local/bin/xmorph";
        command = [ "idle" ];
        workDir = "/run/xmorph-root";
        verbose = true;
        ssh = {
          enable = true;
          port = 2222;
          authorizedKeys = keys.snakeOilEd25519PublicKey;
        };
        tailscale = {
          enable = true;
          authKeyFile = "/run/xmorph-authkey";
          server = "http://headscale";
          # Upstream only carries an explicitly supplied hostname across exec.
          args = "--hostname=rescue";
        };
      };
      # Keep the module's command, privileges and lifecycle intact.
      systemd.services.xmorph-pivot = {
        environment.TS_NO_LOGS_NO_SUPPORT = "1";
        # Upstream tsnet reads this after exec; the server flag only reaches pre-auth.
        environment.TS_CONTROL_URL = "http://headscale";
        serviceConfig.StandardOutput = lib.mkForce "file:/dev/ttyS0";
        serviceConfig.StandardError = lib.mkForce "file:/dev/ttyS0";
      };
      virtualisation.memorySize = 2048;
    };
  };

  testScript = ''
    import json
    import shlex

    def nodes():
        return json.loads(headscale.succeed("headscale nodes list -o json"))

    def rescue():
        matches = [n for n in nodes() if n["givenName"] == "rescue"]
        assert len(matches) == 1, matches
        return matches[0]

    def ssh(ip, command="/bin/cat /etc/pivot-marker", key="/root/allowed"):
        return ("timeout 15 ssh -p 2222 -o LogLevel=ERROR -o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "
                f"-o BatchMode=yes -o IdentitiesOnly=yes -i {key} root@{ip} {shlex.quote(command)}")

    def healthy(machine, ip):
        out = machine.succeed(ssh(ip))
        assert out.strip() == "pivoted-root", out

    def preflight_failure(key):
        before = len(target.get_console_log())
        target.succeed(f"printf '%s' {shlex.quote(key)} > /run/xmorph-authkey; chmod 600 /run/xmorph-authkey")
        target.fail("systemctl start xmorph-pivot", timeout=90)
        target.succeed("systemctl is-active multi-user.target && test -d /nix/store && test ! -e /mnt/oldroot/nix")
        assert "pre-pivot tailscale auth failed; aborting to keep the running OS alive" in target.get_console_log()[before:]
        target.succeed("systemctl reset-failed xmorph-pivot")

    start_all()
    target.wait_for_unit("multi-user.target")
    operator = headscale.succeed("hs-authkey operator").strip()
    outsider = headscale.succeed("hs-authkey outsider").strip()
    headscale.succeed("headscale policy set -f ${allowed}")
    key = headscale.succeed("hs-authkey operator --tags tag:rescue").strip()
    direct.succeed(f"hs-join {operator}")
    relay.succeed(f"hs-join {outsider}")
    for machine in [direct, relay]:
        machine.succeed("install -m600 ${keys.snakeOilEd25519PrivateKey} /root/allowed")
        machine.succeed("ssh-keygen -q -t ed25519 -N \"\" -f /root/denied")

    try:
        with subtest("invalid key aborts before pivot"):
            preflight_failure("tskey-auth-invalid")
            assert not [n for n in nodes() if n["givenName"] == "rescue"]

        with subtest("unreachable control aborts before pivot"):
            headscale.succeed("systemctl stop headscale")
            try:
                preflight_failure(key)
            finally:
                headscale.succeed("systemctl start headscale")
                headscale.wait_for_unit("headscale")
            assert not [n for n in nodes() if n["givenName"] == "rescue"]

        with subtest("module service pivots and reopens persisted tsnet state"):
            target.succeed(f"printf '%s' {shlex.quote(key)} > /run/xmorph-authkey")
            target.succeed("systemctl start --no-block xmorph-pivot")
            direct.wait_until_succeeds("tailscale ip -4 rescue", timeout=120)
            ip = direct.succeed("tailscale ip -4 rescue").strip()
            direct.wait_until_succeeds(f"timeout 5 nc -z {ip} 2222", timeout=120)
            healthy(direct, ip)
            healthy(direct, "rescue.tailnet")
            ip6 = direct.succeed("tailscale ip -6 rescue").strip()
            healthy(direct, ip6)
            assert "pivot_root complete" in target.get_console_log()
            identity = rescue()
            assert "tag:rescue" in identity["tags"], identity
            assert len(nodes()) == 3, nodes()
            direct.succeed(ssh(ip, "test -d /mnt/oldroot/nix/store && test -s /var/lib/tailscale/tailscaled.state"))

        with subtest("SSH over direct and forced DERP paths"):
            direct.wait_until_succeeds("tailscale ping --timeout=3s -c 1 rescue", timeout=90)
            direct.succeed("tailscale status --json | jq -e '.Peer[] | select(.HostName == \"rescue\") | .CurAddr != \"\"'")
            healthy(direct, ip)
            relay.wait_until_succeeds("tailscale ping --until-direct=false --timeout=3s -c 1 rescue | grep 'via DERP(headscale)'", timeout=90)
            relay.wait_until_succeeds(f"timeout 5 nc -z {ip} 2222", timeout=90)
            healthy(relay, ip)
            healthy(relay, ip6)
            for machine in [direct, relay]:
                out = machine.fail(ssh(ip, key="/root/denied") + " 2>&1")
                assert "Permission denied" in out, out
                healthy(machine, ip)

        with subtest("live tag policy denies outsider while operator remains allowed"):
            headscale.succeed("headscale policy set -f ${restricted}")
            relay.wait_until_fails(f"timeout 5 nc -z {ip} 2222", timeout=90)
            relay.succeed("tailscale status --json | jq -e '.Peer[] | select(.HostName == \"rescue\")'")
            relay.succeed("tailscale ping --until-direct=false --timeout=3s -c 1 rescue | grep 'via DERP(headscale)'")
            healthy(direct, ip)
            for address in [ip, ip6]:
                out = relay.fail(ssh(address) + " 2>&1")
                assert "Connection timed out" in out, out
            healthy(direct, ip6)
            headscale.succeed("headscale policy set -f ${allowed}")
            relay.wait_until_succeeds(f"timeout 5 nc -z {ip} 2222", timeout=90)
            healthy(relay, ip)
            healthy(relay, ip6)

        with subtest("control restart preserves identity and application access"):
            headscale.succeed("systemctl stop headscale")
            try:
                healthy(direct, ip)
            finally:
                headscale.succeed("systemctl start headscale")
            headscale.wait_for_unit("headscale")
            relay.wait_until_succeeds(f"timeout 5 nc -z {ip} 2222", timeout=90)
            healthy(relay, ip)
            headscale.wait_until_succeeds("headscale nodes list -o json | jq -e '.[] | select(.givenName == \"rescue\") | .online'", timeout=90)
            after = rescue()
            for field in ["id", "nodeKey", "ipAddresses"]:
                assert identity[field] == after[field], (field, identity, after)
            assert len(nodes()) == 3, nodes()
    finally:
        # A pivot can remove the backdoor; never let driver cleanup hide a failure.
        target.crash()
  '';
}
