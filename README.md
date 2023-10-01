# inferno
Firewall built with eBPF and Go.

# Inspiration
- [When you need to overcome your fear and build your own data-driven eBPF firewall](https://www.youtube.com/watch?v=b7zEnP9W-Cw)

# Usage
- Build with `make`

- Run `./fw --ingress <IP address>` to block ingress traffic from specified IP address

- Run `./fw --egress <IP address>` to block egress traffic to specified IP address
