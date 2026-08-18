# Alpine Maintenance Agent

**Alpine Maintenance Agent** is a portable local assistant for Alpine Linux machines using UEFI, Limine, Ventoy, or a Windows EFI hijack. It turns the collected recovery knowledge into a conservative command-line tool. Its default `doctor` mode is read-only. EFI variables, package changes, and mounts are never modified unless the operator requests a specific action and adds `--yes` after reviewing the exact command.

> The agent is intentionally not an autonomous bootloader replacer. It observes first, explains evidence, and keeps potentially irreversible operations behind explicit human confirmation.

## Design alternatives

| Approach | Tradeoffs | Cost | Setup complexity |
|---|---|---:|---:|
| POSIX shell checks only | Works on very small Alpine installations and has no Python requirement, but offers limited structured reporting and no local language-model explanation | Free | Low |
| **This hybrid CLI** | Uses Python standard library for structured diagnostics and audit logging, works without a cloud service, and can optionally ask a model running on the same LAN or host; requires Python 3 | Free, apart from optional model hardware | Low to moderate |
| Full local model plus automated daemon | Provides richer natural-language reasoning, but consumes substantially more RAM/CPU and needs a model runtime; automatic remediation increases boot and data-loss risk | Depends on local hardware and model | High |

The delivered implementation is the middle option. It remains useful without a model, and a local Ollama-compatible endpoint can be enabled later by setting `OLLAMA_URL` and `OLLAMA_MODEL`. The model can summarize evidence and propose commands, but it cannot execute commands through the agent.

## What it checks

The read-only doctor inspects UEFI mode, efivarfs, EFI boot entries, optional EFI boot files, filesystem capacity, memory availability, crashed OpenRC services, APK upgrade candidates, and kernel error-level messages. It can emit human-readable text or JSON for another local program.

When an EFI partition is supplied, the agent mounts it read-only at a temporary path and checks for `EFI/BOOT/BOOTX64.EFI`, the Limine-hijacked `EFI/Microsoft/Boot/bootmgfw.efi`, and the saved genuine Windows loader `EFI/Microsoft/Boot/bootmgfw_orig.efi`. It never writes to that partition during `doctor`.

## Installation on Alpine

Copy this directory to the Alpine machine. A USB, SSH, or local file transfer is suitable. Then run:

```sh
cd alpine-maintenance-agent
sudo sh install.sh
```

The installer places the executable at `/usr/local/bin/alpine-agent` and the knowledge base at `/usr/local/share/alpine-maintenance-agent/knowledge.md`. The runtime dependency is only Python 3; install it first on a minimal Alpine system if necessary:

```sh
apk add python3
```

The installer does not enable a daemon, edit `/etc/fstab`, change EFI variables, install `efibootmgr`, or upgrade packages.

## Read-only operation

Run a general report:

```sh
sudo alpine-agent doctor
```

Inspect the EFI partition read-only. Replace `/dev/sda1` with the actual EFI System Partition after checking `lsblk -f` or `blkid`:

```sh
sudo alpine-agent --efi-part /dev/sda1 doctor
```

Generate machine-readable output:

```sh
sudo alpine-agent --efi-part /dev/sda1 doctor --json > alpine-report.json
```

Show the embedded knowledge or the local audit log:

```sh
alpine-agent knowledge
sudo alpine-agent audit
```

A nonzero doctor exit code means that at least one warning was observed; it does not mean that the agent changed anything.

## Explicit maintenance actions

Every modifying operation prints the exact command and refuses to continue without root plus `--yes`. The following examples are intentionally separate so the operator can inspect the result of `doctor` first.

If efivarfs is not mounted:

```sh
sudo alpine-agent action mount-efivarfs --yes
```

If `efibootmgr` is missing:

```sh
sudo alpine-agent action install-efibootmgr --yes
```

To activate an existing inactive EFI entry and schedule it for one boot:

```sh
sudo alpine-agent action activate-entry --bootnum 0007 --yes
sudo alpine-agent action set-bootnext --bootnum 0007 --yes
```

To cancel a pending one-time boot request:

```sh
sudo alpine-agent action cancel-bootnext --yes
```

To create a direct one-time Ventoy entry, first verify the disk and partition. Do not reuse `/dev/sda1` by assumption:

```sh
sudo alpine-agent action create-efi-entry \
  --disk /dev/sdb \
  --part 1 \
  --loader '\\EFI\\BOOT\\BOOTX64.EFI' \
  --label 'Ventoy one time' \
  --yes
```

The command prints the new `BootXXXX` number. Then activate it and set it as `BootNext`:

```sh
sudo alpine-agent action activate-entry --bootnum XXXX --yes
sudo alpine-agent action set-bootnext --bootnum XXXX --yes
sudo reboot
```

For direct one-time Windows boot in the hijack layout, the loader must be the saved genuine file, not the hijacked path:

```sh
sudo alpine-agent action create-efi-entry \
  --disk /dev/sda \
  --part 1 \
  --loader '\\EFI\\Microsoft\\Boot\\bootmgfw_orig.efi' \
  --label 'Windows direct one time' \
  --yes
```

## Kernel management

Kernel changes are treated as high-risk operations. The agent never reboots automatically, removes the running kernel, or removes the last detected kernel package. First list the current state:

```sh
sudo alpine-agent action kernel-list
```

Update a selected kernel package, such as the long-term-support kernel:

```sh
sudo alpine-agent action kernel-update --package linux-lts --yes
```

Afterwards inspect `/boot`, run `sudo alpine-agent doctor`, and reboot manually only after reviewing the result. To remove a non-running spare kernel, name it explicitly:

```sh
sudo alpine-agent action kernel-remove --package linux-virt --yes
```

The agent refuses to remove the running kernel flavor or the last detected kernel package.

## Package management

Search and inspect packages without making changes:

```sh
alpine-agent action package-search --query firefox
alpine-agent action package-info --package firefox
```

Install, upgrade, or uninstall packages with explicit confirmation. Package names are validated, and the generic uninstall action refuses base, bootloader, firmware, OpenRC, and kernel packages:

```sh
sudo alpine-agent action package-install --package vim --package git --yes
sudo alpine-agent action package-upgrade --package openssh --yes
sudo alpine-agent action package-uninstall --package unused-package --yes
```

For system-wide operations, use the separately guarded commands:

```sh
sudo alpine-agent action apk-update --yes
sudo alpine-agent action apk-upgrade --yes
```

A backup of `/etc/apk/world` is attempted before package-changing commands. Review `doctor` before and after upgrades.

## OpenRC services and program configuration

Enable or disable an OpenRC service in the default runlevel:

```sh
sudo alpine-agent action service-enable --service crond --yes
sudo alpine-agent action service-disable --service bluetooth --yes
```

For simple `KEY=value` configuration files, update one key atomically and keep a backup:

```sh
sudo alpine-agent action config-set \
  --file /etc/example.conf \
  --format env \
  --key ENABLE_FEATURE \
  --value yes \
  --yes
```

For INI files, supply a section:

```sh
sudo alpine-agent action config-set \
  --file /etc/example.ini \
  --format ini \
  --section application \
  --key theme \
  --value dark \
  --yes
```

The agent only permits configuration paths under `/etc`, `/usr/local/etc`, `/root`, or `/home`, refuses symlinks, writes atomically, and backs up an existing file. It does not guess undocumented application-specific settings.

## Shortcuts and application launchers

Shell aliases are maintained in a separate file under the selected user's home, so the agent does not silently rewrite `.profile` or `.ashrc`:

```sh
sudo alpine-agent action shortcut-add \
  --home /home/alpine \
  --name ll \
  --command 'ls -lah' \
  --yes

. /home/alpine/.config/alpine-agent/shortcuts.sh
```

Remove a managed alias with:

```sh
sudo alpine-agent action shortcut-remove --home /home/alpine --name ll --yes
```

Create a desktop launcher for a graphical application:

```sh
sudo alpine-agent action desktop-entry-create \
  --home /home/alpine \
  --name 'My Editor' \
  --exec 'my-editor %F' \
  --comment 'Open files in My Editor' \
  --categories Utility \
  --yes
```

The launcher is created under `~/.local/share/applications` by default. To remove a launcher, provide its exact `.desktop` path:

```sh
sudo alpine-agent action desktop-entry-remove \
  --desktop-file /home/alpine/.local/share/applications/my-editor.desktop \
  --yes
```

These changes are local and reversible through the audit log and backups under `/var/lib/alpine-maintenance-agent/backups`.

## Network interfaces and OpenRC networking

Inspect interfaces, addresses, and routes without making changes:

```sh
alpine-agent action network-show
alpine-agent action network-config-show --file /etc/network/interfaces
```

Bring a known interface up or down only after verifying the exact name. The operation requires root and `--yes`; taking down the active management interface can disconnect you:

```sh
sudo alpine-agent action interface-up --interface eth0 --yes
sudo alpine-agent action interface-down --interface eth0 --yes
sudo alpine-agent action interface-restart --interface eth0 --yes
```

Install a reviewed persistent network configuration without automatically restarting networking:

```sh
sudo alpine-agent action network-config-install \
  --source /root/interfaces.reviewed \
  --file /etc/network/interfaces \
  --yes
```

After reviewing the backup and configuration, you may control the OpenRC service explicitly:

```sh
sudo alpine-agent action network-service-enable --yes
sudo alpine-agent action network-service-restart --yes
```

The agent does not guess a DHCP/static configuration, add routes, change DNS, change Wi-Fi credentials, or restart networking automatically after writing `/etc/network/interfaces`.

## iptables firewall management

Install the firewall tools and inspect the current rules. IPv4 and IPv6 are managed separately:

```sh
sudo alpine-agent action package-install --package iptables --yes
sudo alpine-agent action firewall-show --family ipv4
sudo alpine-agent action firewall-show --family ipv6
```

Save a timestamped backup before applying any rules:

```sh
sudo alpine-agent action firewall-save --family ipv4 --yes
sudo alpine-agent action firewall-save --family ipv6 --yes
```

Validate a reviewed rules file without changing the active firewall:

```sh
sudo alpine-agent action firewall-validate \
  --family ipv4 \
  --file /root/firewall/rules.v4
```

Apply a validated ruleset. The agent creates an additional current-rules backup immediately before applying it, and it refuses `INPUT DROP` or `FORWARD DROP` policies unless `--allow-drop` is explicitly supplied:

```sh
sudo alpine-agent action firewall-apply \
  --family ipv4 \
  --file /root/firewall/rules.v4 \
  --yes
```

If the reviewed ruleset intentionally uses a default DROP policy, provide the extra acknowledgement only after confirming that SSH or the active management path is explicitly allowed:

```sh
sudo alpine-agent action firewall-apply \
  --family ipv4 \
  --file /root/firewall/rules.v4 \
  --allow-drop \
  --yes
```

To roll back, use the exact backup path printed by the previous command:

```sh
sudo alpine-agent action firewall-restore \
  --family ipv4 \
  --file /var/lib/alpine-maintenance-agent/backups/firewall/TIMESTAMP-ipv4.rules \
  --yes
```

Enable persistence through OpenRC only after reviewing the active rules:

```sh
sudo alpine-agent action firewall-openrc-enable --family ipv4 --yes
sudo alpine-agent action firewall-openrc-save --family ipv4 --yes
sudo alpine-agent action firewall-openrc-enable --family ipv6 --yes
sudo alpine-agent action firewall-openrc-save --family ipv6 --yes
```

Do not apply a default-DROP ruleset over an unverified remote session. On diskless Alpine installations, review whether the firewall files also need to be committed with `lbu ci`. The agent never flushes all rules implicitly and never executes firewall commands through a shell pipeline.

## Optional local-model analysis

The agent has a deterministic report and does not require a model. To enable natural-language analysis, run a local Ollama-compatible HTTP service and set its endpoint and model name in the shell environment. For example:

```sh
export OLLAMA_URL='http://127.0.0.1:11434/api/chat'
export OLLAMA_MODEL='your-local-model'
sudo -E alpine-agent --efi-part /dev/sda1 ask 'Why is the one-time boot request being ignored?'
```

The model receives the embedded knowledge and current diagnostic report. It is instructed not to recommend destructive EFI operations. The agent still keeps actual changes behind the separate `action` command and `--yes` confirmation.

## Optional periodic reporting

The safe way to automate this agent is to schedule **reports**, not repairs. For example, a root cron job can write a JSON report to a protected directory:

```cron
17 3 * * * /usr/local/bin/alpine-agent --efi-part /dev/sda1 doctor --json > /var/log/alpine-maintenance-report.json 2>&1
```

Do not schedule `apk upgrade`, EFI-entry creation, BootNext changes, or bootloader file copies without a separate review workflow. A maintenance report can be inspected after a reboot failure without having caused the failure.

## Scope and limitations

The agent cannot force a vendor's interactive firmware boot-device menu to appear. `BootNext` can request a specific EFI loader for one boot, but the physical one-time boot-menu key remains firmware-specific. If the firmware reports that a selected boot device is disabled, inspect `efibootmgr -v`, look for the active `*` marker, enable USB/External Boot in firmware, and disable Fast Boot. Do not delete the genuine `bootmgfw_orig.efi` backup.

## References

[1]: https://man.archlinux.org/man/efibootmgr.8 "efibootmgr manual — BootNext and EFI entries"

[2]: https://wiki.alpinelinux.org/wiki/Bootloaders "Alpine Linux Bootloaders — efibootmgr usage"

[3]: https://github.com/Limine-Bootloader/Limine/blob/v12.x/USAGE.md "Limine UEFI usage documentation"

[4]: https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface "ArchWiki UEFI documentation"

[5]: https://wiki.alpinelinux.org/wiki/Configure_Networking "Alpine Linux Configure Networking"

[6]: https://wiki.alpinelinux.org/wiki/Iptables "Alpine Linux Iptables"

[7]: https://man7.org/linux/man-pages/man8/iptables-save.8.html "iptables-save manual"

The knowledge base also records these source URLs for the local model and future maintenance reviews.

## Docker container management

Docker operations are separate from APK package management. The agent never installs Docker, enables the Docker service, starts the daemon, or changes containers as a side effect of inspection. Read-only commands include:

```sh
alpine-agent action docker-info
alpine-agent action docker-list
alpine-agent action docker-inspect --container web
alpine-agent action docker-logs --container web --tail 200 --timestamps
alpine-agent action docker-top --container web
alpine-agent action docker-stats --json
```

The lifecycle commands require explicit confirmation and use container names or IDs supplied as separate arguments:

```sh
sudo alpine-agent action docker-start --container web --yes
sudo alpine-agent action docker-stop --container web --timeout 30 --yes
sudo alpine-agent action docker-restart --container web --timeout 30 --yes
sudo alpine-agent action docker-pause --container web --yes
sudo alpine-agent action docker-unpause --container web --yes
```

The agent intentionally does not expose arbitrary `docker run`, `docker exec`, prune, volume removal, network removal, image removal, privileged-mode changes, mount changes, port changes, or restart-policy changes. These operations have a substantially larger security or data-loss surface and should be reviewed separately. Docker service state is managed through OpenRC:

```sh
alpine-agent action docker-service-status
sudo alpine-agent action docker-service-enable --yes
sudo alpine-agent action docker-service-start --yes
sudo alpine-agent action docker-service-restart --yes
```

The Docker daemon must be running and accessible to the invoking user. On Alpine, the service is normally managed through `rc-service` and `rc-update`, not systemd. Container statistics use Docker's `docker stats --no-stream` output, including CPU, memory, network I/O, block I/O, and PIDs [8].

## System resource monitoring

Generate a read-only host report containing load average, CPU count, uptime, memory, swap, filesystems, network byte counters, and a bounded process snapshot:

```sh
alpine-agent resource-report
alpine-agent resource-report --json > /tmp/resource-report.json
alpine-agent resource-report --with-docker --json > /tmp/resource-and-docker.json
```

The default warning thresholds are less than 10% available memory, at least 90% filesystem use, and a one-minute load average greater than one per CPU. They can be adjusted for a report without changing the system:

```sh
alpine-agent resource-report \
  --memory-warn 15 \
  --disk-warn 85 \
  --load-warn 1.5 \
  --top 10
```

For a bounded live view, specify a duration and interval. The command always stops at the duration limit and never performs automatic remediation:

```sh
alpine-agent resource-watch \
  --duration 300 \
  --interval 10 \
  --with-docker
```

The monitoring implementation reads Linux `/proc`, filesystem statistics, network counters, and optional Docker stats. It reports warnings but does not kill processes, restart containers, alter firewall rules, upgrade packages, or change kernel settings. This separation is intentional: schedule reports externally if desired, but do not turn monitoring thresholds into unattended repair actions.

## References for Docker and monitoring

[8]: https://docs.docker.com/reference/cli/docker/container/stats/ "Docker container stats"

[9]: https://docs.docker.com/reference/cli/docker/container/ "Docker container CLI"

[10]: https://wiki.alpinelinux.org/wiki/OpenRC "Alpine Linux OpenRC"

[11]: https://docs.kernel.org/filesystems/proc.html "Linux kernel proc filesystem documentation"
