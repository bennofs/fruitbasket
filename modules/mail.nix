{ config, pkgs, ... }:
let
  hostname = "mail.${config.fsr.domain}";
  domain = config.fsr.domain;
  rspamd-domain = "rspamd.${config.fsr.domain}";
  # brauchen wir das überhaupt?
  #ldap-aliases = pkgs.writeText "ldap-aliases.cf" ''
  #server_host = ldap://localhost
  #search_base = ou=mail, dc=ifsr, dc=de
  #'';
  dovecot-ldap-args = pkgs.writeText "ldap-args" ''
    uris = ldap://localhost
    dn = uid=search, ou=users, dc=ifsr, dc=de
    auth_bind = yes
    !include ${config.sops.secrets."dovecot_ldap_search".path}

    ldap_version = 3
    scope = subtree
    base = dc=ifsr, dc=de
    user_filter = (&(objectClass=posixAccount)(uid=%n))
    pass_filter = (&(objectClass=posixAccount)(uid=%n))
  '';
in
{
  sops.secrets."rspamd-password".owner = config.users.users.rspamd.name;
  sops.secrets."dovecot_ldap_search".owner = config.services.dovecot2.user;

  networking.firewall.allowedTCPPorts = [ 25 465 993 ];

  services = {
    postfix = {
      enable = true;
      hostname = "${hostname}";
      domain = "${domain}";
      relayHost = "";
      origin = "${domain}";
      destination = [ "${hostname}" "${domain}" "localhost" ];
      sslCert = "/var/lib/acme/${hostname}/fullchain.pem";
      sslKey = "/var/lib/acme/${hostname}/key.pem";
      config = {
        smtpd_recipient_restrictions = [
          "reject_unauth_destination"
          "permit_sasl_authenticated"
          "permit_mynetworks"
        ];
        #alias_maps = [ "ldap:${ldap-aliases}" ];
        smtpd_sasl_auth_enable = true;
        smtpd_sasl_path = "/var/lib/postfix/auth";
        virtual_mailbox_base = "/var/mail";
      };
    };
    dovecot2 = {
      enable = true;
      enableImap = true;
      enableQuota = false;
      sslServerCert = "/var/lib/acme/${hostname}/fullchain.pem";
      sslServerKey = "/var/lib/acme/${hostname}/key.pem";
      mailboxes = {
        Spam = {
          auto = "create";
          specialUse = "Junk";
        };
        Sent = {
          auto = "create";
          specialUse = "Sent";
        };
        Drafts = {
          auto = "create";
          specialUse = "Drafts";
        };
        Trash = {
          auto = "create";
          specialUse = "Trash";
        };
      };
      extraConfig = ''
        mail_location = maildir:/var/mail/%u
        passdb {
          driver = ldap
          args = ${dovecot-ldap-args}
        }
        userdb {
          driver = ldap
          args = ${dovecot-ldap-args}
        }
        service auth {
          unix_listener /var/lib/postfix/auth {
               group = postfix
               mode = 0660
               user = postfix
            }
        }
      '';
    };
    rspamd = {
      enable = true;
      postfix.enable = true;
      locals = {
        "worker-controller.inc".source = config.sops.secrets."rspamd-password".path;
        "redis.conf".text = ''
          read_servers = "127.0.0.1";
          write_servers = "127.0.0.1";
        '';
        "dkim_signing.conf".text = ''
          path = "/var/lib/rspamd/dkim/$domain.$selector.key";
          selector = "quitte";
          sign_authenticated = true;
          use_domain = "header";
        '';
      };
    };
    redis = {
      vmOverCommit = true;
      servers.rspamd = {
        enable = true;
        port = 6379;
      };
    };
    nginx = {
      enable = true;
      recommendedGzipSettings = true;
      recommendedOptimisation = true;
      recommendedProxySettings = true;
      recommendedTlsSettings = true;

      virtualHosts."${hostname}" = {
        forceSSL = true;
        enableACME = true;
      };
      virtualHosts."${rspamd-domain}" = {
        forceSSL = true;
        enableACME = true;
        locations = {
          "/" = {
            proxyPass = "http://127.0.0.1:11334";
            proxyWebsockets = true;
          };
        };
      };
    };
  };
}
























