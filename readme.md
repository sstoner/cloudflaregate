# Cloudflare Gate - Traefik Plugin

A [Traefik](https://traefik.io) plugin that restricts access to your applications to only allow traffic proxied through Cloudflare. This helps protect your applications from direct access attempts and ensures traffic comes through Cloudflare's security infrastructure.

[![Build Status](https://github.com/sstoner/cloudflaregate/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/sstoner/cloudflaregate/actions)  [![goreport](https://goreportcard.com/badge/github.com/sstoner/cloudflaregate)](https://goreportcard.com/report/github.com/sstoner/cloudflaregate) [![Latest Release](https://img.shields.io/github/v/release/sstoner/cloudflaregate)](https://github.com/sstoner/cloudflaregate/releases/latest)

## Features

- Validates that incoming requests originate from Cloudflare's IP ranges
- Automatic periodic updates of Cloudflare IP ranges
- Allow additional IP addresses or CIDR ranges

## Configuration

### Static Configuration

To use this plugin in your Traefik instance, register it in the static configuration:

```yaml
# Static configuration
experimental:
  plugins:
    cloudflaregate:
      moduleName: github.com/sstoner/cloudflaregate
      version: v1.0.0
```

### Dynamic Configuration

Configure the middleware in your dynamic configuration:

```yaml
# Dynamic configuration
http:
  middlewares:
    cloudflare-gate:
      plugin:
        cloudflaregate:
          # Optional: configure IP ranges refresh interval (default: 24h)
          refreshInterval: "24h"
          # Allow internal traffic
          allowedIPs:
            - "192.168.1.0/24"

  routers:
    my-router:
      rule: Host(`app.example.com`)
      service: my-service
      middlewares:
        - cloudflare-gate
      entryPoints:
        - websecure

  services:
    my-service:
      loadBalancer:
        servers:
          - url: http://internal-service:8080
```

## Configuration Options

| Option           | Type       | Default | Description                                                  |
|-----------------|------------|---------|--------------------------------------------------------------|
| `refreshInterval`| string    | `24h`   | Interval for updating Cloudflare IP ranges (minimum: 1s)     |
| `allowedIPs`    | []string   | `[]`    | List of additional IP addresses or CIDR ranges to allow      |

### Example Configuration

```yaml
# Static configuration
experimental:
  plugins:
    cloudflaregate:
      moduleName: github.com/sstoner/cloudflaregate
      version: v1.0.0
      allowedIPs:
        - "192.168.1.0/24"
        - "10.0.0.0/8"
```

## Security Features

### IP Range Validation
- Automatically fetches and updates Cloudflare's IP ranges
- Validates that incoming requests originate from Cloudflare IPs
- Periodic background updates of IP ranges


## Development

### Prerequisites
- Go 1.22.0 or later
- Traefik 2.x

### Building
```bash
# Clone the repository
git clone https://github.com/sstoner/cloudflaregate
cd cloudflaregate

# Run tests
make test

# Build
go build ./...
```

### Testing Locally

For local testing, use Traefik's development mode:

```yaml
# Static configuration
experimental:
  localPlugins:
    cloudflaregate:
      moduleName: github.com/sstoner/cloudflaregate
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Traefik team for their plugin system
- Cloudflare for providing their IP ranges publicly

## Support

If you encounter any issues or have questions:
- Open an issue on [GitHub](https://github.com/sstoner/cloudflaregate/issues)
- Check existing issues for solutions
