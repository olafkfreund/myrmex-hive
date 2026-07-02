{
  description = "Myrmex Hive: Secure Agent Orchestrator & Gateway";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      nixosModule = { config, lib, pkgs, ... }:
        let
          cfg = config.services.myrmex-hive;
        in
        {
          options.services.myrmex-hive = {
            enable = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Enable Myrmex Hive service.";
            };
            role = lib.mkOption {
              type = lib.types.enum [ "gateway" "agent" ];
              default = "agent";
              description = "Role to run: gateway or agent.";
            };
            configPath = lib.mkOption {
              type = lib.types.path;
              description = "Path to configuration JSON file.";
            };
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              description = "Myrmex Hive package to use.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.myrmex-hive = {
              description = "Myrmex Hive Service (${cfg.role})";
              after = [ "network.target" ];
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart = if cfg.role == "gateway" then
                  "${cfg.package}/bin/gateway -config ${cfg.configPath}"
                else
                  "${cfg.package}/bin/agent -config ${cfg.configPath}";
                Restart = "always";
                DynamicUser = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                NoNewPrivileges = true;
              };
            };
          };
        };
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        
        myrmexPackage = pkgs.buildGoModule {
          pname = "myrmex-hive";
          version = "1.0.0";
          src = ./.;
          vendorHash = null; # uses vendor directory directly
        };
      in
      {
        packages = {
          default = myrmexPackage;
          myrmex-hive = myrmexPackage;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            just
            docker-compose
          ];
        };
      }
    ) // {
      nixosModules.default = nixosModule;
      nixosModules.myrmex-hive = nixosModule;
    };
}
