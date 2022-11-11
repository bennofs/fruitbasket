{
  inputs = {
    nixpkgs.url = github:revol-xut/nixpkgs/nixos-22.05;
    #nixpkgs.url = github:revol-xut/nixpkgs/master;
    sops-nix.url = github:Mic92/sops-nix;
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";
    fsr-infoscreen.url = github:fsr/infoscreen;
  };
  outputs = { self, nixpkgs, sops-nix, fsr-infoscreen, ... }@inputs:
    let
    in {
      #packages."aarch64-linux".sanddorn = self.nixosConfigurations.sanddorn.config.system.build.sdImage;
      packages."x86_64-linux".quitte = self.nixosConfigurations.quitte.config.system.build.vm;
      packages."x86_64-linux".default = self.packages."x86_64-linux".quitte;

      nixosConfigurations = {
        birne = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            ./hosts/birne/configuration.nix

            ./modules/base.nix
            ./modules/autoupdate.nix
            ./modules/desktop.nix
            ./modules/printing.nix
            ./modules/wifi.nix
            ./modules/options.nix
            {
              fsr.enable_office_bloat = true;
            }

          ];
        };
        sanddorn = nixpkgs.lib.nixosSystem {
          system = "aarch64-linux";
          modules = [
            {
              nixpkgs.overlays = [ fsr-infoscreen.overlay."aarch64-linux" ];
              nixpkgs.config.allowBroken = true;
              sdImage.compressImage = false;
            }
            ./hosts/sanddorn/configuration.nix
            ./modules/infoscreen.nix
            ./modules/base.nix
            ./modules/autoupdate.nix
            ./modules/wifi.nix
            ./modules/desktop.nix
            ./modules/options.nix
            "${nixpkgs}/nixos/modules/installer/sd-card/sd-image-aarch64.nix"
            {
              fsr.enable_office_bloat = false;
            }
          ];
        };
        quitte = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            inputs.sops-nix.nixosModules.sops
            ./hosts/quitte/configuration.nix
            ./modules/base.nix
            ./modules/sops.nix
            ./modules/keycloak.nix
            ./modules/nginx.nix
            ./modules/hedgedoc.nix
            ./modules/wiki.nix
            ./modules/stream.nix
            {
              sops.defaultSopsFile = ./secrets/quitte.yaml;
            }
          ];
        };
        quitte-vm = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            inputs.sops-nix.nixosModules.sops
            ./modules/base.nix
            ./modules/sops.nix
            ./modules/keycloak.nix
            ./modules/nginx.nix
            ./modules/hedgedoc.nix
            ./modules/wiki.nix
            ./modules/stream.nix
            ./modules/vm.nix
            "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
            {
              _module.args.buildVM = true;
              sops.defaultSopsFile = ./secrets/durian.yaml;
            }
          ];
        };
      };
    };
}
