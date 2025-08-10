#!/bin/sh
# dhclient exit hook for FND client
# shellcheck disable=SC2154
FND_RUN_DIR=/run/fnd
FND_DHCP_IP_FILE="$FND_RUN_DIR/dhcp_server_ip"
mkdir -p "$FND_RUN_DIR"
if [ -n "$new_fnd_server_ip" ]; then
  echo "$new_fnd_server_ip" > "$FND_DHCP_IP_FILE".new
  mv "$FND_DHCP_IP_FILE".new "$FND_DHCP_IP_FILE"
  # Signal service (best effort)
  systemctl kill -s SIGUSR1 fnd-client.service 2>/dev/null || true
fi
exit 0
