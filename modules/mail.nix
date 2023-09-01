{ config, pkgs, lib, ... }:
let
  hostname = "mail.${config.fsr.domain}";
  domain = config.fsr.domain;
  rspamd-domain = "rspamd.${config.fsr.domain}";
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
  sops.secrets."postfix_ldap_aliases".owner = config.services.postfix.user;

  networking.firewall.allowedTCPPorts = [
    25 # insecure SMTP
    465
    587 # SMTP
    993 # IMAP
    4190 # sieve
  ];
  users.users.postfix.extraGroups = [ "opendkim" ];

  services = {
    postfix = {
      enable = true;
      enableSubmission = true;
      enableSubmissions = true;
      hostname = "${hostname}";
      domain = "${domain}";
      origin = "${domain}";
      destination = [ "${hostname}" "${domain}" "localhost" ];
      networksStyle = "host"; # localhost and own public IP
      sslCert = "/var/lib/acme/${hostname}/fullchain.pem";
      sslKey = "/var/lib/acme/${hostname}/key.pem";
      relayDomains = [ "hash:/var/lib/mailman/data/postfix_domains" ];

      extraAliases = ''
        # Taken from kaki, maybe we can throw out some at some point
        # General redirections for pseudo accounts
        bin:            root
        daemon:         root
        named:          root
        nobody:         root
        uucp:           root
        www:            root
        ftp-bugs:       root
        postfix:        root

        # Well-known aliases
        manager:        root
        dumper:         root
        operator:       root
        abuse:          postmaster
        postmaster:     root

        # trap decode to catch security attacks
        decode:         root

        # yeet into the void
        noreply:        /dev/null
      '';
      config = {
        home_mailbox = "Maildir/";
        # hostname used in helo command. It is recommended to have this match the reverse dns entry
        # smtp_helo_name = "x8d1e1ea9.agdsn.tu-dresden.de";
        smtp_helo_name = config.networking.rdns;
        smtp_use_tls = true;
        # smtp_tls_security_level = "encrypt";
        smtpd_use_tls = true;
        # smtpd_tls_security_level = lib.mkForce "encrypt";
        # smtpd_tls_auth_only = true;
        smtpd_tls_protocols = [
          "!SSLv2"
          "!SSLv3"
          "!TLSv1"
          "!TLSv1.1"
        ];
        # "reject_non_fqdn_hostname"
        smtpd_recipient_restrictions = [
          "permit_sasl_authenticated"
          "permit_mynetworks"
          "reject_unauth_destination"
          "reject_non_fqdn_sender"
          "reject_non_fqdn_recipient"
          "reject_unknown_sender_domain"
          "reject_unknown_recipient_domain"
          "reject_unauth_destination"
          "reject_unauth_pipelining"
          "reject_invalid_hostname"
          "check_policy_service inet:localhost:12340"
        ];
        smtpd_relay_restrictions = [
          "permit_sasl_authenticated"
          "permit_mynetworks"
          "reject_unauth_destination"
        ];
        # smtpd_sender_login_maps = [ "ldap:${ldap-senders}" ];
        alias_maps = [ "hash:/etc/aliases" ];
        alias_database = [ "hash:/etc/aliases" ];
        # alias_maps = [ "hash:/etc/aliases" "ldap:${ldap-aliases}" ];
        smtpd_milters = [ "local:/run/opendkim/opendkim.sock" ];
        non_smtpd_milters = [ "local:/var/run/opendkim/opendkim.sock" ];
        smtpd_sasl_auth_enable = true;
        smtpd_sasl_path = "/var/lib/postfix/auth";
        smtpd_sasl_type = "dovecot";
        #mailman stuff
        mailbox_transport = "lmtp:unix:/run/dovecot2/dovecot-lmtp";

        transport_maps = [ "hash:/var/lib/mailman/data/postfix_lmtp" ];
        local_recipient_maps = [ "hash:/var/lib/mailman/data/postfix_lmtp" "ldap:${config.sops.secrets."postfix_ldap_aliases".path}" "$alias_maps" ];
      };
    };
    dovecot2 = {
      enable = true;
      enableImap = true;
      enableQuota = true;
      quotaGlobalPerUser = "10G";
      enableLmtp = true;
      mailLocation = "maildir:~/Maildir";
      sslServerCert = "/var/lib/acme/${hostname}/fullchain.pem";
      sslServerKey = "/var/lib/acme/${hostname}/key.pem";
      protocols = [ "imap" "sieve" ];
      mailPlugins = {
        perProtocol = {
          imap = {
            enable = [ ];
          };
          lmtp = {
            enable = [ "sieve" ];
          };
        };
      };
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
      modules = [
        pkgs.dovecot_pigeonhole
      ];
      extraConfig = ''
        auth_username_format = %Ln
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
        service managesieve-login {
          inet_listener sieve {
            port = 4190
          }
          service_count = 1
        }
        service lmtp {
          unix_listener dovecot-lmtp {
            group = postfix
            mode = 0600
            user = postfix
          }
          client_limit = 1
        }
      '';
    };
    opendkim = {
      enable = true;
      domains = "csl:${config.fsr.domain}";
      selector = config.networking.hostName;
      configFile = pkgs.writeText "opendkim-config" ''
        UMask 0117
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
  security.acme.certs."${domain}" = {
    reloadServices = [
      "postfix.service"
      "dovecot2.service"
    ];
  };
}
