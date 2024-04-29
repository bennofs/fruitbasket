{ config, pkgs, ... }:
let
  domain = "monitoring.${config.networking.domain}";
in
{
  # grafana configuration
  services.grafana = {
    enable = true;
    settings = {
      server = {
        inherit domain;
        http_addr = "127.0.0.1";
        http_port = 2342;
      };
      database = {
        type = "postgres";
        user = "grafana";
        host = "/run/postgresql";
      };

    };


  };

  services.postgresql = {
    enable = true;
    ensureUsers = [
      {
        name = "grafana";
        ensureDBOwnership = true;
      }
    ];
    ensureDatabases = [ "grafana" ];
  };

  services.prometheus = {
    enable = true;
    port = 9001;
    exporters = {
      node = {
        enable = true;
        enabledCollectors = [ "systemd" ];
        port = 9002;
      };
    };
    scrapeConfigs = [
      {
        job_name = "node";
        static_configs = [{
          targets = [ "127.0.0.1:${toString config.services.prometheus.exporters.node.port}" ];
        }];
        scrape_interval = "15s";
      }
    ];
  };

  # nginx reverse proxy
  services.nginx.virtualHosts.${domain} = {
    locations."/" = {
      proxyPass = "http://localhost:${toString config.services.grafana.port}";
      proxyWebsockets = true;
    };
  };
}
