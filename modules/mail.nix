{ config, pkgs, ... }:
let
  hostname = "mail.${config.fsr.domain}";
  domain = config.fsr.domain;
in
{
  sops.secrets."rspamd-password".owner = config.users.users.rspamd.name;

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
        smtpd_sasl_auth_enable = true;
        smtpd_sasl_path = "/var/lib/postfix/auth";
        virtual_mailbox_base = "/var/spool/mail";
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
        auth_mechanisms = plain login
        disable_plaintext_auth = no
        userdb {
          driver = passwd
          args = blocking=no
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
        locations = {
          "/rspamd" = {
            proxyWebsockets = true;

            # maybe there is a more beautiful way for this
            extraConfig = ''
              if ($request_uri ~* "/rspamd/(.*)") {
                proxy_pass http://127.0.0.1:11334/$1;
              }
            '';
          };
        };
      };
    };
  };
}
