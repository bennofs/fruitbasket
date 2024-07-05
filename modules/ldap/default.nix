{ config, pkgs, system, ... }:
let
  domain = "auth.${config.networking.domain}";
  # seedSettings = {
  #   groups = [
  #     {
  #       name = "admins";
  #       long_name = "Portunus Admin";
  #       members = [ "admin" ];
  #       permissions.portunus.is_admin = true;
  #     }
  #     {
  #       name = "search";
  #       long_name = "LDAP search group";
  #       members = [ "search" ];
  #       permissions.ldap.can_read = true;
  #     }
  #     {
  #       name = "fsr";
  #       long_name = "Mitglieder des iFSR";
  #     }
  #   ];
  #   users = [
  #     {
  #       login_name = "admin";
  #       given_name = "admin";
  #       family_name = "admin";
  #       password.from_command = [
  #         "${pkgs.coreutils}/bin/cat"
  #         config.sops.secrets."portunus/admin-password".path
  #       ];
  #     }
  #     {
  #       login_name = "search";
  #       given_name = "search";
  #       family_name = "search";
  #       password.from_command = [
  #         "${pkgs.coreutils}/bin/cat"
  #         config.sops.secrets."portunus/search-password".path
  #       ];
  #     }
  #   ];
  # };
in
{
  # sops.secrets = {
  #   "portunus/admin-password".owner = config.services.portunus.user;
  #   "portunus/search-password".owner = config.services.portunus.user;
  # };

  # services.portunus = {
  #   enable = true;
  #   package = pkgs.portunus.overrideAttrs (_old: {
  #     patches = [
  #       ./0001-update-user-validation-regex.patch
  #       ./0002-both-ldap-and-ldaps.patch
  #       ./0003-gecos-ascii-escape.patch
  #       ./0004-make-givenName-optional.patch
  #     ];
  #     doCheck = false; # posix regex related tests break
  #   });

  #   inherit domain seedSettings;
  #   port = 8681;
  #   ldap = {
  #     suffix = "dc=ifsr,dc=de";
  #     searchUserName = "search";

  #     # normally disables port 389 (but not with our patch), use 636 with tls
  #     # `portunus.domain` resolves to localhost
  #     tls = true;
  #   };
  # };
  services.openldap = {
    enable = true;
    urlList = [ "ldap:///" "ldaps:///" ];
    settings = {
      attrs = {
        olcLogLevel = "conns";

        olcTLSCACertificateFile = "/var/lib/acme/${domain}/full.pem";
        olcTLSCertificateFile = "/var/lib/acme/${domain}/cert.pem";
        olcTLSCertificateKeyFile = "/var/lib/acme/${domain}/key.pem";
        # olcTLSCipherSuite = "HIGH:MEDIUM:+3DES:+RC4:+aNULL";
        olcTLSCRLCheck = "none";
        olcTLSVerifyClient = "never";
        olcTLSProtocolMin = "3.1";

      };
      children = {
        "cn=schema".includes = [
          "${pkgs.openldap}/etc/schema/core.ldif"
          # attributetype ( 9999.1.1 NAME 'isMemberOf'
          # DESC 'back-reference to groups this user is a member of'
          # SUP distinguishedName )
          "${pkgs.openldap}/etc/schema/cosine.ldif"
          "${pkgs.openldap}/etc/schema/inetorgperson.ldif"
          "${pkgs.openldap}/etc/schema/nis.ldif"
          # "${pkgs.writeText "openssh.schema" ''
          # 	attributetype ( 9999.1.2 NAME 'sshPublicKey'
          # 		DESC 'SSH public key used by this user'
          # 		SUP name )
          # ''}"
        ];

        "olcDatabase={1}mdb" = {
          attrs = {
            objectClass = [ "olcDatabaseConfig" "olcMdbConfig" ];

            olcDatabase = "{1}mdb";
            olcDbDirectory = "/var/lib/openldap/data";

            olcSuffix = "dc=ifsr,dc=de";

            /* your admin account, do not use writeText on a production system */
            olcRootDN = "cn=portunus,dc=ifsr,dc=de";
            olcRootPW = "{CRYPT}$y$j9T$xdf4HigfhmQWXn.bw9MgH/$91evhYAV1GP7olNCkQoCpUZrghh5P8dDXcZdAtpiD32";

            olcAccess = [
              /* custom access rules for userPassword attributes */
              ''{0}to attrs=userPassword
                by self write
                by anonymous auth
                by * none''

              /* allow read on anything else */
              ''{1}to *
                 by dn.base="cn=portunus,dc=ifsr,dc=de" write
                 by group.exact="cn=portunus-viewers,dc=ifsr,dc=de" read
                 by self read
                 by anonymous auth
            ''
            ];
          };
          children = {
            "olcOverlay={2}memberof".attrs = {
              objectClass = [ "olcOverlayConfig" "olcMemberOf" "top" ];
              olcOverlay = "{2}memberof";
              olcMemberOfRefInt = "TRUE";
              olcMemberOfDangling = "ignore";
              olcMemberOfGroupOC = "groupOfNames";
              olcMemberOfMemberAD = "member";
              olcMemberOfMemberOfAD = "memberOf";
            };
          };
        };
      };
    };
  };

  systemd.services.openldap = {
    wants = [ "acme-${domain}.service" ];
    after = [ "acme-${domain}.service" ];
  };
  # security.acme.defaults.group = "certs";
  # users.groups.certs.members = [ "openldap" ];
  # certificate permissions
  users.users.openldap.extraGroups = [ "nginx" ];

  security.pam.services.sshd.makeHomeDir = true;

  services.nginx = {
    enable = true;
    virtualHosts."${domain}" = {
      # locations = {
      #   "/".proxyPass = "http://localhost:${toString config.services.portunus.port}";
      # };
    };
  };
  networking.firewall = {
    extraInputRules = ''
      ip saddr { 141.30.86.192/26, 141.30.30.169, 10.88.0.1/16 } tcp dport 636 accept comment "Allow ldaps access from office nets and podman"
    '';
  };
}
