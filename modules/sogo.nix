{ config, pkgs, ... }:
let
  sogo-hostname = "mail.${config.fsr.domain}";
  domain = config.fsr.domain;
in
{
  sops.secrets.ldap_search = {
    owner = config.systemd.services.sogo.serviceConfig.User;
  };
  sops.secrets.postgres_sogo = {
    owner = config.systemd.services.sogo.serviceConfig.User;
  };

  services = {
    sogo = {
      enable = true;
      language = "German";
      extraConfig = ''
                WOWorkersCount = 10;
                SOGoUserSources = ({
                  type = ldap;
                  CNFieldName = cn;
                  UIDFieldName = uid;
                  baseDN = "ou = users, dc=ifsr, dc=de";
                  bindDN = "uid=search, ou=users, dc=ifsr, dc=de";
                  bindPassword = LDAP_SEARCH;
                  hostname = "ldap://localhost";
                  canAuthenticate = YES;
                  id = directory;
      
                });
                SOGoProfileURL = "postgresql://sogo:sogo@localhost:5432/sogo/sogo_user_profile";    
        		SOGoFolderInfoURL = "postgreql://sogo:sogo@localhost:5432/sogo/sogo_folder_info";
        		OCSSessionsFolderURL = "postgresql://sogo:sogo@localhost:5432/sogo/sogo_sessions_folder";
      ''; # Hier ist bindPassword noch nicht vollständig
      configReplaces = {
        LDAP_SEARCH = config.sops.secrets.ldap_search.path; 
      };
      vhostName = "${sogo-hostname}";
      timezone = "Europe/Berlin";
    };
      postgresql = {
        enable = true;
        ensureUsers = [
          {
            name = "sogo";
            ensurePermissions = {
              "DATABASE sogo" = "ALL PRIVILEGES";
            };
          }
        ];
        ensureDatabases = [ "sogo" ];
      };

    nginx = {
      recommendedProxySettings = true;
      virtualHosts."${sogo-hostname}" = {
        forceSSL = true;
        enableACME = true;
        locations = {
          "/" = {
            proxyPass = "http://127.0.0.1:20000";
            proxyWebsockets = true;
          };
        };
      };
    };
  };

  systemd.services.sogo.after = [ "sogo-pgsetup.service" ];

  systemd.services.sogo-pgsetup = {
    description = "Prepare Sogo postgres database";
    wantedBy = [ "multi-user.target" ];
    after = [ "networking.target" "postgresql.service" ];
    serviceConfig.Type = "oneshot";

    path = [ pkgs.sudo config.services.postgresql.package ];
    script = ''
      sudo -u ${config.services.postgresql.superUser} psql -c "ALTER ROLE sogo WITH PASSWORD '$(cat ${config.sops.secrets.postgres_sogo.path})'"
    '';
  };

}
