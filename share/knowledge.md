# Alpine Linux Maintenance Knowledge Base

## Mission and safety policy

This agent is a local maintenance assistant for Alpine Linux systems that use UEFI and may use Limine as a boot manager. The default mode is read-only. It may inspect system state, package status, OpenRC services, kernel errors, EFI variables, and boot files. It must never format a partition, overwrite an EFI loader, delete a Windows loader backup, modify the boot order, install packages, or reboot the machine without an explicit human-approved action.

The genuine Windows loader in the user's hijack layout is saved as:

`EFI/Microsoft/Boot/bootmgfw_orig.efi`

The hijacked path is:

`EFI/Microsoft/Boot/bootmgfw.efi`

The Limine fallback loader is normally:

`EFI/BOOT/BOOTX64.EFI`

The agent must preserve `bootmgfw_orig.efi` and must not recommend replacing it with another file.

## UEFI mode and variables

`efibootmgr` works only when Linux was booted in UEFI mode with EFI runtime variables available. The relevant directory is `/sys/firmware/efi`; the variable filesystem is normally mounted at `/sys/firmware/efi/efivars`.

If needed, an administrator may mount it with:

```sh
mount -t efivarfs efivarfs /sys/firmware/efi/efivars
```

The UEFI `BootNext` variable requests one specific boot entry for the next boot only. The firmware should consume it after the attempt and then return to the ordinary `BootOrder`. In `efibootmgr`, `-n XXXX` sets BootNext, `-N` clears it, `-a -b XXXX` activates an inactive entry, and `-c` creates a new entry.

A one-shot request is not the same thing as the firmware's interactive boot-device list. `efibootmgr` can request a specific EFI file but generally cannot force the vendor's graphical boot menu to appear. To show that menu, use the hardware one-time boot key or firmware setup. If the key is ignored, cold power-off, the built-in keyboard, disabling Fast Boot, and enabling USB/External Boot are the appropriate recovery steps.

## Inspecting EFI entries

Use:

```sh
efibootmgr -v
```

An active entry is normally marked with `*`. If an entry exists but has no `*`, it may be inactive. The agent may propose:

```sh
efibootmgr -a -b XXXX
efibootmgr -n XXXX
```

but must require explicit confirmation before executing these commands.

## One-time Ventoy boot

The correct disk and partition must be identified first; never assume `/dev/sda1`. A typical Ventoy UEFI loader is:

`\\EFI\\BOOT\\BOOTX64.EFI`

A one-time entry can be created with:

```sh
efibootmgr -c -d /dev/sdX -p N -L 'Ventoy one time' -l '\\EFI\\BOOT\\BOOTX64.EFI' --unicode
efibootmgr -a -b XXXX
efibootmgr -n XXXX
```

The agent must show the exact disk, partition, loader, and label before asking for confirmation. It must not execute this action merely because the device was guessed from a prior conversation.

## One-time direct Windows boot

Because the Windows path is hijacked, a direct one-shot entry should point to the saved genuine loader rather than the hijacked file:

`\\EFI\\Microsoft\\Boot\\bootmgfw_orig.efi`

Example:

```sh
efibootmgr -c -d /dev/sdX -p N -L 'Windows direct one time' -l '\\EFI\\Microsoft\\Boot\\bootmgfw_orig.efi' --unicode
efibootmgr -a -b XXXX
efibootmgr -n XXXX
```

This is still a firmware-variable change and requires explicit confirmation. The agent must warn that the entry's disk and partition must contain the path.

## Boot-loop diagnosis

If the system repeatedly returns to Limine, likely causes include the firmware ignoring a hotkey, Fast Boot bypassing keyboard detection, an inactive or disabled EFI entry, a stale BootNext value, Secure Boot rejecting an unsigned loader, or ordinary fallback to the hijacked Windows path. The agent should collect `efibootmgr -v`, `blkid`, EFI mode, efivarfs availability, and the presence of `bootmgfw_orig.efi` before recommending changes.

The agent should not recommend destructive commands such as `mkfs`, `dd`, deleting EFI files, or blindly copying files over `bootmgfw.efi`. Any EFI repair should be a separate, explicitly confirmed operation with a verified backup.

## Alpine maintenance

Useful read-only checks include `apk version -l '<'` for available package upgrades, `df -h -P` for full filesystems, `rc-status --crashed` for crashed OpenRC services, `/proc/meminfo` for memory availability, and `dmesg -T --level=err,crit,alert,emerg` for kernel errors.

Package changes should be separated into two steps. First inspect available upgrades. Then, only after explicit confirmation, run `apk update` and `apk upgrade`. The agent must never combine an automatic upgrade with a bootloader or EFI repair.

## Local AI behavior

The deterministic doctor is authoritative for observations. An optional local model may explain the report, but it must not be allowed to execute arbitrary commands. When a local model is used, its role is to summarize evidence and propose low-risk next steps. All changes remain behind the agent's explicit action commands, root requirement, and `--yes` confirmation.

## Source references

- `https://man.archlinux.org/man/efibootmgr.8`
- `https://wiki.alpinelinux.org/wiki/Bootloaders`
- `https://github.com/Limine-Bootloader/Limine/blob/v12.x/USAGE.md`
- `https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface`

## Kernel lifecycle management

Kernel operations are high impact because a failed kernel or initramfs update can make the machine unbootable. The agent must list the running kernel with `uname -r`, inspect installed `linux-*` packages, keep at least one spare kernel, and refuse to remove the running kernel flavor or the last detected kernel package.

A kernel update is an explicit package operation, normally:

```sh
apk add --upgrade linux-lts
```

The agent must not reboot automatically after a kernel update. The operator should inspect `/boot`, confirm the new kernel and initramfs are present, run `doctor`, and choose the reboot manually. Kernel removal is allowed only for a named non-running spare kernel and must create a backup of `/etc/apk/world` first.

## APK package operations

The agent may search packages with `apk search -v`, inspect metadata with `apk info -a`, install with `apk add`, upgrade selected packages with `apk add --upgrade`, uninstall with `apk del`, refresh indexes with `apk update`, and upgrade the system with `apk upgrade`. Package names are validated so option injection is not possible. The agent refuses to uninstall protected base, bootloader, OpenRC, musl, BusyBox, firmware, or kernel packages through the generic uninstall command.

Every package-changing operation requires root, an exact preview, explicit `--yes`, and an audit entry. A backup of `/etc/apk/world` is attempted before changes. Kernel operations use separate commands and stricter checks.

## OpenRC services

Service changes use `rc-update add SERVICE default` or `rc-update del SERVICE default`. The agent validates service names and never starts or restarts services implicitly. Service changes require explicit confirmation. A later version may add a separate start/restart command only with a similarly visible confirmation gate.

## Shortcuts and application configuration

Shell shortcuts are stored in a managed file under the target user's home, `.config/alpine-agent/shortcuts.sh`. The agent replaces only the named alias and does not edit arbitrary shell startup files automatically. The user may source the file from `.profile`, `.ashrc`, or another shell startup file manually.

Desktop launchers are written as validated `.desktop` files under the user's `~/.local/share/applications` by default. Newlines are rejected from launcher fields, and the launcher path must remain under `/root` or `/home`.

Generic program settings are edited through `config-set` in either simple `KEY=value` format or INI format. Approved configuration paths are limited to `/etc`, `/usr/local/etc`, `/root`, and `/home`. Existing files are backed up before replacement, writes are atomic, and symlinks are refused. The agent does not infer undocumented application schemas; the operator must provide the exact file, key, section when needed, and value.

## Automation boundary

The agent can generate periodic read-only reports. It must not run unattended kernel updates, package removal, boot-entry creation, shortcut changes, or application configuration changes from cron without an explicit external approval workflow. A scheduled report is safe; an unattended repair loop is not.

## Network-interface and firewall management

Alpine normally manages persistent interface configuration through `/etc/network/interfaces` and the `networking` OpenRC service. Use `ip -brief link`, `ip -brief address`, and `ip route` for read-only inspection. The agent does not guess interface names, routes, DNS, Wi-Fi credentials, or connection managers.

The network actions `interface-up`, `interface-down`, and `interface-restart` require an exact interface name and explicit confirmation. `network-service-restart` warns that the active connection may drop. `network-config-install` backs up the existing file, writes the new file atomically, and does not restart networking automatically. This is intentional: an incorrect persistent network file can make the machine unreachable.

Alpine's iptables workflow uses the `iptables` OpenRC service for IPv4 and `ip6tables` for IPv6 where available. `firewall-show` is read-only. `firewall-save` writes a timestamped rules backup. `firewall-validate` uses `iptables-restore --test` or `ip6tables-restore --test`. `firewall-apply` and `firewall-restore` validate first, create a current-rules backup, and then apply the supplied rules through stdin rather than a shell. Rulesets that set `INPUT` or `FORWARD` to `DROP` are refused unless `--allow-drop` is explicitly supplied, because this can disconnect SSH or other remote administration.

The firewall actions keep IPv4 and IPv6 separate. `firewall-openrc-enable` adds the appropriate service to the default runlevel, and `firewall-openrc-save` invokes the OpenRC save operation. On diskless Alpine systems, the operator may additionally need to commit the configuration with `lbu ci` after reviewing the changes.

Never use a firewall apply command over an unverified remote session with a default DROP policy. Always keep the generated backup path from the command output. To roll back, validate and apply that backup file with the matching address family. The agent never flushes all rules implicitly.

References:

- Alpine Configure Networking: https://wiki.alpinelinux.org/wiki/Configure_Networking
- Alpine Iptables: https://wiki.alpinelinux.org/wiki/Iptables
- iptables-save manual: https://man7.org/linux/man-pages/man8/iptables-save.8.html

## Docker container management

Docker inspection should remain read-only by default. Safe observation commands include `docker info`, `docker version`, `docker container ls --all`, `docker container inspect`, `docker container logs`, `docker container top`, and `docker container stats --all --no-stream`. Docker stats includes CPU, memory, network I/O, block I/O, and PIDs; stopped containers do not provide live stats.

Mutating actions require exact validated container names or IDs, Docker daemon access, and explicit root/user confirmation. The first implementation allows only start, stop, restart, pause, and unpause. It intentionally excludes arbitrary `docker run`, arbitrary `docker exec`, prune commands, volume/image/network deletion, privileged changes, mount changes, published-port changes, and restart-policy changes.

Alpine uses OpenRC. Docker service actions should use `rc-service docker status|start|stop|restart` and persistence should use `rc-update add docker default` or `rc-update del docker default`. Inspection must not install or start Docker implicitly.

## System resource monitoring

Read-only resource reporting may use `/proc/loadavg`, `/proc/uptime`, `/proc/meminfo`, `/proc/net/dev`, `df -P -k`, `ps`, and optional Docker stats. Reports should identify thresholds and warn on low available memory, high filesystem usage, or high load per CPU. Docker's displayed memory percentage is a Docker CLI metric and should not be silently conflated with raw `/proc/meminfo` values.

The agent's watch mode is bounded by duration and interval. It emits observations only; thresholds must never trigger process kills, container restarts, firewall changes, package operations, kernel operations, or boot changes. Periodic reporting may be scheduled externally, but unattended self-repair is outside the safety model.

Sources:

- Docker container CLI: https://docs.docker.com/reference/cli/docker/container/
- Docker container stats: https://docs.docker.com/reference/cli/docker/container/stats/
- Alpine OpenRC: https://wiki.alpinelinux.org/wiki/OpenRC
- Linux proc filesystem: https://docs.kernel.org/filesystems/proc.html
