{ config, pkgs, ... }:
let
  domain = "rspamd.${config.networking.domain}";
in
{
  sops.secrets."rspamd-password".owner = config.users.users.rspamd.name;
  users.users.rspamd.extraGroups = [ "redis-rspamd" ];
  services = {
    rspamd = {
      enable = true;
      postfix.enable = true;
      locals = {
        "worker-controller.inc".source = config.sops.secrets."rspamd-password".path;
        "redis.conf".text = ''
          read_servers = "/run/redis-rspamd/redis.sock";
          write_servers = "/run/redis-rspamd/redis.sock";
        '';
        # headers in spamassasin style to not break old sieve scripts
        "worker-proxy.inc".text = ''
          spam_header = "X-Spam-Flag";
        '';
        "milter_headers.conf".text = ''
          use = ["x-spam-level", "x-spam-status", "x-spamd-result", "authentication-results" ];
        '';
        "neural.conf".text = ''
          servers = "/run/redis-rspamd/redis.sock";
          enabled = true;
        '';
        "neural_group.conf".text = ''
          symbols = {
            "NEURAL_SPAM" {
              weight = 0.5; # fairly low weight since we don't know how this will behave
              description = "Neural network spam";
            }
            "NEURAL_HAM" {
              weight = -0.5;
              description = "Neural network ham";
            }
          }
        '';
        "dmarc.conf".text = ''
          reporting {
            enabled = true;
            email = 'noreply-dmarc@${config.networking.domain}';
            domain = '${config.networking.domain}';
            org_name = '${config.networking.domain}';
            from_name = 'DMARC Aggregate Report';
          }
        '';
        "dkim_signing.conf".text = ''
          selector = "quitte2024";
          allow_username_mismatch = true;
          allow_hdrfrom_mismatch = true;
          use_domain_sign_local = "ifsr.de";
          path = /var/lib/rspamd/dkim/$domain.$selector.key;

        '';
        "reputation.conf".text = ''
          rules {
            ip_reputation = {
              selector "ip" {
              }
              backend "redis" {
                servers = "/run/redis-rspamd/redis.sock";
              }

              symbol = "IP_REPUTATION";
            }
            spf_reputation =  {
              selector "spf" {
              }
              backend "redis" {
                servers = "/run/redis-rspamd/redis.sock";
              }

              symbol = "SPF_REPUTATION";
            }
            dkim_reputation =  {
              selector "dkim" {
              }
              backend "redis" {
                servers = "/run/redis-rspamd/redis.sock";
              }

              symbol = "DKIM_REPUTATION"; # Also adjusts scores for DKIM_ALLOW, DKIM_REJECT
            }
            generic_reputation =  {
              selector "generic" {
                selector = "ip"; # see https://rspamd.com/doc/configuration/selectors.html
              }
              backend "redis" {
                servers = "/run/redis-rspamd/redis.sock";
              }

              symbol = "GENERIC_REPUTATION";
            }
          }
        '';
        "groups.conf".text = ''
            group "reputation" {
              symbols = {
                  "IP_REPUTATION_HAM" {
                      weight = 1.0;
                  }
                  "IP_REPUTATION_SPAM" {
                      weight = 4.0;
                  }

                  "DKIM_REPUTATION" {
                      weight = 1.0;
                  }

                  "SPF_REPUTATION_HAM" {
                      weight = 1.0;
                  }
                  "SPF_REPUTATION_SPAM" {
                      weight = 2.0;
                  }

                  "GENERIC_REPUTATION" {
                      weight = 1.0;
                  }
              }
          }
        '';

        "multimap.conf".text =
          let
            local_ips = pkgs.writeText "localhost.map" ''
              ::1
              127.0.0.1
            '';
            tud_ips = pkgs.writeText "tud.map" ''
              141.30.0.0/16
              141.76.0.0/16
            '';
          in
          ''
            WHITELIST_SENDER_DOMAIN {
              type = "from";
              filter = "email:domain";
              map = "/var/lib/rspamd/whitelist.sender.domain.map";
              action = "accept";
              regexp = true;
            }
            WHITELIST_SENDER_EMAIL {
              type = "from";
              map = "/var/lib/rspamd/whitelist.sender.email.map";
              action = "accept";
              regexp = true;
            }
            BLACKLIST_SENDER_DOMAIN {
              type = "from";
              filter = "email:domain";
              map = "/var/lib/rspamd/blacklist.sender.domain.map";
              action = "reject";
              regexp = true;
            }
            BLACKLIST_SENDER_EMAIL {
              type = "from";
              map = "/var/lib/rspamd/blacklist.sender.email.map";
              action = "reject";
              regexp = true;
            }
            BLACKLIST_SUBJECT_KEYWORDS {
              type = "header";
              header = "Subject"
              map = "/var/lib/rspamd/blacklist.keyword.subject.map";
              action = "reject";
              regexp = true;
            }
            RECEIVED_LOCALHOST {
              type = "ip";
              action = "accept";
              map = ${local_ips};
            }
            RECEIVED_TU_NETWORKS {
              type = "ip";
              map = ${tud_ips};
            }
          '';
      };
    };
    redis = {
      vmOverCommit = true;
      servers.rspamd = {
        enable = true;
      };
    };
    nginx = {
      virtualHosts."${domain}" = {
        locations = {
          "/" = {
            proxyPass = "http://127.0.0.1:11334";
            proxyWebsockets = true;
          };
        };
      };
    };
  };
  systemd = {
    services.rspamd-dmarc-report = {
      description = "rspamd dmarc reporter";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.rspamd}/bin/rspamadm dmarc_report -v";
        User = "rspamd";
        Group = "rspamd";
      };
      startAt = "daily";
    };
  };
}
