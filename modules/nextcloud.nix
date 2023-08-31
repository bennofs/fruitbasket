{ config, pkgs, lib, ... }:
let
  domain = "nc.${config.fsr.domain}";
in
{
  sops.secrets = {
    nextcloud_adminpass.owner = "nextcloud";
    nextcloud_ldap_search = {
      key = "portunus/search-password";
      owner = "nextcloud";
    };
  };

  services = {
    nextcloud = {
      enable = true;
      package = pkgs.nextcloud25;
      enableBrokenCiphersForSSE = false; # disable the openssl warning
      hostName = domain;
      https = true; # Use https for all urls
      phpExtraExtensions = all: [
        all.ldap # Enable ldap php extension
      ];
      config = {
        dbtype = "pgsql";
        adminpassFile = config.sops.secrets.nextcloud_adminpass.path;
        adminuser = "root";
      };
      # postgres database is configured automatically
      database.createLocally = true;
    };

    # Enable ACME and force SSL
    nginx.virtualHosts.${domain} = {
      enableACME = true;
      forceSSL = true;
    };
  };

  # ensure that postgres is running *before* running the setup
  systemd.services."nextcloud-setup" = {
    requires = [ "postgresql.service" ];
    after = [ "postgresql.service" ];
  };

  # configure some settings automatically
  systemd.services."phpfpm-nextcloud" =
    let
      occ = lib.getExe config.services.nextcloud.occ;
      ldapConfig = rec {
        ldapAgentName = "uid=search,ou=users,${ldapBase}";
        ldapBase = config.services.portunus.ldap.suffix;
        ldapBaseGroups = "ou=groups,${ldapBase}";
        ldapBaseUsers = "ou=users,${ldapBase}";
        ldapConfigurationActive = "1";
        ldapEmailAttribute = "mail";
        ldapGroupFilterObjectclass = "groupOfNames";
        ldapGroupMemberAssocAttr = "member";
        ldapHost = "localhost";
        ldapPort = "389";
        ldapUserDisplayName = "cn";
        ldapUserFilterObjectclass = "posixAccount";
        # generated by nextcloud
        ldapGroupFilter = "(&(|(objectclass=groupOfNames)))";
        ldapUserFilter = "(|(objectclass=posixAccount))";
        ldapLoginFilter = "(&(|(objectclass=posixAccount))(uid=%uid))";
      };
      preStart = pkgs.writeScript "nextcloud-preStart" ''
        # enable included LDAP app
        ${occ} app:enable user_ldap

        # set up new LDAP config if it does not exist
        if ! ${occ} ldap:show-config s01 > /dev/null; then
          ${occ} ldap:create-empty-config
        fi

        # update LDAP config
        ${lib.concatLines (lib.mapAttrsToList (name: value: "${occ} ldap:set-config s01 '${name}' '${value}'") ldapConfig)}
        ${occ} ldap:set-config s01 'ldapAgentPassword' $(cat ${config.sops.secrets.nextcloud_ldap_search.path})
      '';
    in
    {
      # run the whole preStart as nextcloud user, so that the log won't be cluttered by lots of sudo calls
      serviceConfig.ExecStartPre = "/run/wrappers/bin/sudo -u nextcloud --preserve-env=NEXTCLOUD_CONFIG_DIR --preserve-env=OC_PASS ${preStart}";
    };
}
