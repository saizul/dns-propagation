#!/usr/bin/env sh
# Typical session after moving a site to a new server.
set -eu

DOMAIN=${1:-example.com}
NEW_IP=${2:-203.0.113.10}

# 1. What do the authoritative servers say, and how many public resolvers agree yet?
dns-propagation check "$DOMAIN" A --authoritative

# 2. Same check over DNS over HTTPS (useful on networks that intercept port 53).
dns-propagation check "$DOMAIN" A --expect "$NEW_IP" --doh || true

# 3. Block until 100% of resolvers return the new address, at most one hour.
dns-propagation watch "$DOMAIN" A --expect "$NEW_IP" --interval 60 --max-wait 3600

# 4. Moving mail too? Check MX, SPF, DMARC and DKIM in one go.
dns-propagation email "$DOMAIN" --selector google
