# Docker and system monitoring research

## Docker lifecycle

Docker's official `docker container` command group includes list, inspect, logs, start, stop, restart, pause, unpause, remove, exec, and stats operations. The agent should expose a narrow, validated subset rather than arbitrary Docker CLI passthrough. Read-only operations include `docker info`, `docker ps`, `docker inspect`, `docker logs`, `docker top`, and `docker stats --no-stream`. Mutating operations require root or Docker socket access plus an explicit confirmation.

Docker's `docker stats` provides live runtime metrics. The documented fields include CPU percentage, memory usage/limit, memory percentage, network I/O, block I/O, and PIDs. The CLI's Linux memory display subtracts cache usage, so the agent should report Docker's output as provided and avoid mixing it with raw host memory numbers without labeling the difference.

A Docker service on Alpine is normally managed by OpenRC. Service actions should use `rc-service docker start|stop|restart` and persistence should use `rc-update add docker default` or the equivalent explicit runlevel command. The agent must not automatically install, enable, start, or restart Docker as a side effect of inspection.

## Host resource monitoring

The Linux `/proc` filesystem exposes kernel and process information. Read-only monitoring can use `/proc/loadavg`, `/proc/meminfo`, `/proc/stat`, `/proc/uptime`, `/proc/net/dev`, `/sys/class/net`, `df -P`, `free`, and `ps` when available. The agent should handle missing files or commands gracefully on minimal Alpine installations.

The resource report should include load averages, CPU count, memory and swap totals/availability, uptime, filesystem usage, top processes where `ps` is available, network byte counters, and optional Docker container stats. JSON output is useful for periodic reports. A bounded watch mode must limit both sampling interval and duration; it must never run forever unless the operator deliberately chooses a non-default option.

## Safety boundaries

Do not expose arbitrary `docker run`, `docker exec`, or shell execution. Container names and IDs should be validated, and any command passed to `docker exec` should be supplied as separate arguments rather than through a shell. The agent should refuse destructive actions such as container removal unless `--yes` is supplied, and should warn before stopping or restarting a container.

Container prune, image prune, volume prune, network prune, and system prune are destructive and should not be included in the first implementation. The agent should not alter published ports, mounts, capabilities, privileged mode, restart policies, or resource limits automatically.

Resource monitoring is observation-only. Thresholds may generate warnings in a report, but must not trigger kills, container restarts, package changes, or firewall changes. Optional periodic reporting should be implemented through an external scheduler or OpenRC-managed script, not an unattended self-repair loop.

## References

- Docker container CLI: https://docs.docker.com/reference/cli/docker/container/
- Docker container stats: https://docs.docker.com/reference/cli/docker/container/stats/
- Alpine OpenRC: https://wiki.alpinelinux.org/wiki/OpenRC
- Linux proc filesystem: https://docs.kernel.org/filesystems/proc.html
