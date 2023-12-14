{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";
    nix-index-database.url = "github:nix-community/nix-index-database";
    nix-index-database.inputs.nixpkgs.follows = "nixpkgs";
    kpp.url = "github:fsr/kpp";
    kpp.inputs.nixpkgs.follows = "nixpkgs";
    ese-manual.url = "git+https://git.ifsr.de/ese/manual-website";
    ese-manual.inputs.nixpkgs.follows = "nixpkgs";

    course-management = {
      url = "github:fsr/course-management";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { self, nixpkgs, sops-nix, nix-index-database, kpp, ese-manual, course-management, ... }@inputs:
    {
      packages."x86_64-linux".quitte = self.nixosConfigurations.quitte.config.system.build.toplevel;
      packages."x86_64-linux".default = self.packages."x86_64-linux".quitte;
      formatter.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.nixpkgs-fmt;
      hydraJobs."x86-64-linux".quitte = self.packages."x86_64-linux".quitte;

      overlays.default = import ./overlays;
      nixosConfigurations = {
        quitte = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          specialArgs = inputs;
          modules = [
            inputs.sops-nix.nixosModules.sops
            inputs.kpp.nixosModules.default
            inputs.nix-index-database.nixosModules.nix-index
            ese-manual.nixosModules.default
            course-management.nixosModules.default
            ./hosts/quitte/configuration.nix
            ./modules/bacula.nix
            ./modules/options.nix
            ./modules/base.nix
            ./modules/sops.nix
            ./modules/kpp.nix
            ./modules/ldap
            ./modules/mail
            ./modules/mailman.nix
            ./modules/nginx.nix
            # ./modules/hydra.nix
            ./modules/userdir.nix
            ./modules/hedgedoc.nix
            ./modules/padlist.nix
            ./modules/postgres.nix
            ./modules/wiki.nix
            ./modules/ftp.nix
            #./modules/stream.nix
            ./modules/nextcloud.nix
            ./modules/matrix.nix
            ./modules/mautrix-telegram.nix
            ./modules/sogo.nix
            ./modules/vaultwarden.nix
            ./modules/website.nix
            ./modules/zsh.nix
            ./modules/course-management.nix
            ./modules/courses-phil.nix
            ./modules/gitea.nix
            ./modules/fail2ban.nix
            ./modules/kanboard.nix
            ./modules/infoscreen.nix
            ./modules/manual.nix
            ./modules/sharepic.nix
            ./modules/zammad.nix
            {
              nixpkgs.overlays = [ self.overlays.default ];
              sops.defaultSopsFile = ./secrets/quitte.yaml;
            }
          ];
        };
        tomate = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          specialArgs = inputs;
          modules = [
            inputs.sops-nix.nixosModules.sops
            inputs.nix-index-database.nixosModules.nix-index
            ./hosts/tomate/configuration.nix
            ./modules/base.nix
            ./modules/zsh.nix
            ./modules/fail2ban.nix
            ./modules/sssd.nix
            {
              sops.defaultSopsFile = ./secrets/tomate.yaml;
            }
          ];
        };
      };
    };
}
