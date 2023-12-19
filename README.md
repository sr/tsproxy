# Tailscale Proxy

tsproxy is an HTTP reverse proxy that configures a Tailscale device for each upstream.

This command exposes the backend at `http://my-app` and `https://my-app.<tailnet-name>.ts.net`:

`tsproxy --upstream=my-app=http://127.0.0.1:8000`

**NOTE:** [MagicDNS](https://tailscale.com/kb/1081/magicdns/) must be enabled.

Repeat the `--upstream` flag for each backends.

## Funnel

Backends can be exposed on the public Internet using [Tailscale Funnel](https://tailscale.com/kb/1223/tailscale-funnel/). Use the `funnel` option:

`tsproxy --upstream=my-public-app=http://127.0.0.1:8000;funnel`

## Prometheus

`tsproxy` serves metrics about itself and [Prometheus HTTP Service Discovery](https://prometheus.io/docs/prometheus/latest/http_sd/) targets on the host's two tailscale IPs.

To add an upstream to service discovery, use the `prometheus` option:

`tsproxy --upstream=my-app=http://127.0.0.1:8000;prometheus`

Then use this Prometheus scrape config:


```yaml
- job_name: tsproxy
  http_sd_configs:
    - url: http://<tsproxy-host>:<tsproxy-port>/sd
```

The tsproxy metrics port (flag `--port`) defaults to `32019`. It's automatically registered in service discovery.

## Authentication Headers

The proxy sets the `X-Webauth-User` and `X-Webauth-Name` headers for requests made by users. This works well with [Grafana's Auth Proxy](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-proxy/).

Requests originating from tagged nodes (this includes Tailscale's Funnel nodes) are proxied as is, without any additional headers.

## Tailscale ACLs

To add the ACL tag `tag:tsnet` to all devices created by tsproxy, create an [Auth key](https://tailscale.com/kb/1085/auth-keys/), then run the process with `TS_AUTH_KEY=<key>`. All upstreams will automatically be tagged.

This works well for ACLs.

```json
  "acls": [
    {"action": "accept", "src": ["group:admin"], "dst": ["tag:tsnet:80,443"]},
  ],
```

To change the ACL tag, update `TS_AUTH_KEY` and set `FORCE_REAUTH=1`.

## systemd

This is the systemd unit I use to run `tsproxy`: <https://gist.github.com/sr/f8b1860cca428b04fc2b0b84ea561348>.
