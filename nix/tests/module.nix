# End-to-end test of the NixOS module: boot a VM, enable services.jaynshare
# with a seeded config, and assert the service starts, binds its port, and the
# app answers on /jaynshare/status with the seeded account. Uses an apikey
# account so startup performs no OAuth refresh or other network call (NixOS test
# VMs have no network) — the key is never exercised, only parsed.
{
  pkgs,
  self,
  system,
}:

let
  seedConfig = pkgs.writeText "jaynshare-seed.json" (builtins.toJSON {
    proxy = {
      port = 3456;
      apiKey = "tc-test-secret";
    };
    upstream = "https://api.anthropic.com";
    accounts = [
      {
        name = "test-apikey";
        type = "apikey";
        apiKey = "sk-ant-api03-dummy-not-used";
      }
    ];
  });
in
pkgs.testers.runNixOSTest {
  name = "jaynshare-module";

  nodes.machine =
    { ... }:
    {
      imports = [ self.nixosModules.jaynshare ];

      environment.systemPackages = [ pkgs.curl ];

      services.jaynshare = {
        enable = true;
        package = self.packages.${system}.jaynshare;
        # configSource is typed `str`; interpolate the derivation to its
        # store-path string (which also pulls it into the VM's closure).
        configSource = "${seedConfig}";
      };
    };

  testScript = ''
    machine.wait_for_unit("jaynshare.service")
    machine.wait_for_open_port(3456)

    # Loopback is exempt from the proxy-key gate, so this needs no api key.
    # A 200 proves the server is up and routing; the seeded account name in the
    # body proves configSource was copied and parsed by the app.
    status = machine.succeed("curl -sf http://127.0.0.1:3456/jaynshare/status")
    assert "test-apikey" in status, f"seeded account missing from status: {status}"

    # The mutable config was materialized at the module's default path.
    machine.succeed("test -f /var/lib/jaynshare/jaynshare.json")
  '';
}
