#!/usr/bin/env python3
"""alpine_agent: conservative local Alpine Linux maintenance assistant.

The default behavior is read-only. Operations that modify packages, kernels,
EFI variables, mounts, services, shortcuts, or application configuration
require root and an explicit --yes flag. No cloud service is required. An
optional Ollama-compatible local model may be used for natural-language
analysis when OLLAMA_URL and OLLAMA_MODEL are set.
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_NAME = "alpine-maintenance-agent"
BASE_DIR = Path(__file__).resolve().parent
KNOWLEDGE_PATH = Path(os.environ.get("ALPINE_AGENT_KNOWLEDGE", BASE_DIR / "share" / "knowledge.md"))
STATE_DIR = Path(os.environ.get("ALPINE_AGENT_STATE", "/var/lib/alpine-maintenance-agent"))
LOG_PATH = STATE_DIR / "audit.log"
BACKUP_DIR = STATE_DIR / "backups"

PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+@-]*$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@+-]+$")
ALIAS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]*$")
PROTECTED_PACKAGES = {
    "alpine-base",
    "apk-tools",
    "busybox",
    "musl",
    "openrc",
    "linux-firmware",
    "limine",
    "grub",
    "grub-efi",
    "syslinux",
}
CONFIG_ROOTS = (Path("/etc"), Path("/usr/local/etc"), Path("/root"), Path("/home"))

ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[34m"
ANSI_RESET = "\033[0m"


@dataclass
class Check:
    name: str
    status: str
    summary: str
    details: str = ""
    risk: str = "read-only"


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def color(text: str, code: str, enabled: bool = True) -> str:
    return f"{code}{text}{ANSI_RESET}" if enabled else text


def have(command: str) -> bool:
    return shutil.which(command) is not None


def run(command: list[str], timeout: int = 20) -> CommandResult:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(command, proc.returncode, proc.stdout.strip(), proc.stderr.strip())
    except FileNotFoundError:
        return CommandResult(command, 127, "", f"command not found: {command[0]}")
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return CommandResult(command, 124, stdout.strip(), "command timed out")
    except Exception as exc:  # defensive: diagnostics must not crash the agent
        return CommandResult(command, 1, "", f"{type(exc).__name__}: {exc}")


def run_with_input(command: list[str], input_text: str, timeout: int = 30) -> CommandResult:
    try:
        proc = subprocess.run(command, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(command, proc.returncode, proc.stdout.strip(), proc.stderr.strip())
    except FileNotFoundError:
        return CommandResult(command, 127, "", f"command not found: {command[0]}")
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return CommandResult(command, 124, stdout.strip(), "command timed out")
    except Exception as exc:
        return CommandResult(command, 1, "", f"{type(exc).__name__}: {exc}")


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def is_mounted(path: str) -> bool:
    try:
        mounts = Path("/proc/mounts").read_text(errors="replace")
    except OSError:
        return False
    return any(line.split()[1] == path for line in mounts.splitlines() if len(line.split()) >= 2)


def append_audit(event: str, result: str = "") -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).isoformat()
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp}\t{event}\t{result.replace(chr(10), ' ')}\n")
    except OSError:
        pass


def read_text(path: str | Path, limit: int = 20000) -> str:
    try:
        return Path(path).read_text(errors="replace")[:limit]
    except OSError as exc:
        return f"unavailable: {exc}"


def parse_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read_text("/proc/meminfo", 10000).splitlines():
        match = re.match(r"^(\w+):\s+(\d+)", line)
        if match:
            values[match.group(1)] = int(match.group(2))
    return values


def check_platform() -> Check:
    efi = Path("/sys/firmware/efi")
    if efi.exists():
        size = read_text(efi / "fw_platform_size", 100).strip()
        return Check("UEFI mode", "OK", f"UEFI runtime directory is present ({size or 'platform size unknown'}).")
    return Check("UEFI mode", "WARN", "UEFI runtime directory is absent; efibootmgr and EFI variable operations may not work.", risk="read-only")


def check_efivarfs() -> Check:
    path = "/sys/firmware/efi/efivars"
    if is_mounted(path):
        return Check("EFI variables", "OK", "efivarfs is mounted and available.")
    if Path(path).exists():
        return Check("EFI variables", "WARN", "The efivars directory exists but is not mounted.", "Use: mount -t efivarfs efivarfs /sys/firmware/efi/efivars", "mount change")
    return Check("EFI variables", "WARN", "efivars is unavailable.", "BootNext cannot be inspected or changed until the system is booted in UEFI mode.")


def check_efi_entries() -> Check:
    if not have("efibootmgr"):
        return Check("EFI boot entries", "WARN", "efibootmgr is not installed.", "Install only when needed: apk add efibootmgr", "package change")
    result = run(["efibootmgr", "-v"])
    if result.returncode != 0:
        return Check("EFI boot entries", "WARN", "efibootmgr could not read firmware variables.", result.stderr or result.stdout)
    bootnext = "BootNext:" in result.stdout
    entries = [line.strip() for line in result.stdout.splitlines() if re.search(r"^Boot[0-9A-Fa-f]{4}\s", line)]
    inactive_count = sum(1 for line in entries if not re.search(r"^Boot[0-9A-Fa-f]{4}\*", line))
    summary = "EFI boot entries readable"
    if bootnext:
        summary += "; BootNext is currently set"
    if inactive_count:
        summary += f"; {inactive_count} entry/entries inactive"
    return Check("EFI boot entries", "OK" if inactive_count == 0 else "WARN", summary, result.stdout)


def check_boot_files(efi_part: str | None = None) -> Check:
    if not efi_part:
        return Check("Boot files", "INFO", "No EFI partition supplied; file checks skipped.", "Run with --efi-part /dev/sdXY to inspect the EFI partition.")
    if not Path(efi_part).exists():
        return Check("Boot files", "WARN", f"EFI partition {efi_part} does not exist.")
    mount_dir = Path("/run/alpine-agent-efi")
    if is_mounted(str(mount_dir)):
        mounted_here = False
    else:
        mounted_here = True
        try:
            mount_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return Check("Boot files", "WARN", "Cannot create a temporary read-only mount point.", str(exc), "mount change")
        mount_result = run(["mount", "-o", "ro", efi_part, str(mount_dir)])
        if mount_result.returncode != 0:
            return Check("Boot files", "WARN", f"Could not mount {efi_part} read-only.", mount_result.stderr or mount_result.stdout, "mount change")
    paths = {
        "Limine fallback": mount_dir / "EFI/BOOT/BOOTX64.EFI",
        "hijack path": mount_dir / "EFI/Microsoft/Boot/bootmgfw.efi",
        "Windows backup": mount_dir / "EFI/Microsoft/Boot/bootmgfw_orig.efi",
    }
    present = [f"{name}: {'present' if path.exists() else 'MISSING'}" for name, path in paths.items()]
    if mounted_here:
        run(["umount", str(mount_dir)])
    missing = [name for name, path in paths.items() if not path.exists()]
    return Check("Boot files", "WARN" if missing else "OK", "; ".join(present), risk="read-only")


def check_storage() -> Check:
    result = run(["df", "-h", "-P"])
    if result.returncode != 0:
        return Check("Storage", "WARN", "df could not read filesystems.", result.stderr)
    warnings: list[str] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 6 and fields[4].rstrip("%").isdigit() and int(fields[4].rstrip("%")) >= 90:
            warnings.append(f"{fields[5]} is {fields[4]} full")
    return Check("Storage", "WARN" if warnings else "OK", "; ".join(warnings) if warnings else "No mounted filesystem is at or above 90%.", result.stdout)


def check_memory() -> Check:
    info = parse_meminfo()
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    if not total:
        return Check("Memory", "INFO", "Memory information unavailable.")
    percent = round(100 * available / total)
    return Check("Memory", "WARN" if percent < 10 else "OK", f"Approximately {percent}% of memory is available.", f"MemTotal={total} kB; MemAvailable={available} kB")


def check_services() -> Check:
    if not have("rc-status"):
        return Check("OpenRC services", "INFO", "rc-status is not installed or this is not an OpenRC environment.")
    result = run(["rc-status", "--crashed"])
    if result.returncode == 0 and result.stdout.strip():
        return Check("OpenRC services", "WARN", "OpenRC reports crashed services.", result.stdout)
    return Check("OpenRC services", "OK", "No crashed OpenRC services reported.", result.stdout or result.stderr)


def check_packages() -> Check:
    if not have("apk"):
        return Check("APK packages", "INFO", "apk is unavailable; package checks skipped.")
    result = run(["apk", "version", "-l", "<"], timeout=30)
    if result.returncode != 0:
        return Check("APK packages", "WARN", "Could not determine available package upgrades.", result.stderr or result.stdout)
    upgrades = [line for line in result.stdout.splitlines() if line.strip()]
    return Check("APK packages", "WARN" if upgrades else "OK", f"{len(upgrades)} package upgrade candidate(s) reported.", "\n".join(upgrades[:100]))


def check_kernel_logs() -> Check:
    if have("dmesg"):
        result = run(["dmesg", "-T", "--level=err,crit,alert,emerg"], timeout=15)
        if result.stdout:
            return Check("Kernel errors", "WARN", "Kernel error-level messages are present.", result.stdout[-8000:])
    return Check("Kernel errors", "OK", "No readable kernel error-level messages were found.")


def collect_report(efi_part: str | None = None) -> dict[str, Any]:
    checks = [
        check_platform(),
        check_efivarfs(),
        check_efi_entries(),
        check_boot_files(efi_part),
        check_storage(),
        check_memory(),
        check_services(),
        check_packages(),
        check_kernel_logs(),
    ]
    warnings = [check for check in checks if check.status == "WARN"]
    return {
        "agent": APP_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": [asdict(check) for check in checks],
        "warning_count": len(warnings),
        "safe_mode": True,
    }


def report_text(report: dict[str, Any]) -> str:
    lines = [f"{report['agent']} report — {report['timestamp']}", ""]
    for item in report["checks"]:
        marker = {"OK": "OK", "WARN": "WARN", "INFO": "INFO"}.get(item["status"], item["status"])
        lines.append(f"[{marker}] {item['name']}: {item['summary']}")
        if item.get("details"):
            lines.append(textwrap.indent(item["details"], "    "))
    lines.append("")
    lines.append(f"Warnings: {report['warning_count']}. Default mode is read-only.")
    return "\n".join(lines)


def load_knowledge() -> str:
    if KNOWLEDGE_PATH.exists():
        return KNOWLEDGE_PATH.read_text(encoding="utf-8", errors="replace")
    return "No knowledge file found. Use the built-in checks and conservative defaults."


def local_model_answer(prompt: str, report: dict[str, Any]) -> str:
    url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/chat")
    model = os.environ.get("OLLAMA_MODEL", "")
    if not model:
        return "No local model configured. Set OLLAMA_MODEL and optionally OLLAMA_URL, or use the deterministic doctor report."
    system = (
        "You are a conservative Alpine Linux maintenance assistant. Use only the supplied report and knowledge. "
        "Never recommend destructive commands such as mkfs, dd, rm of EFI files, or blind bootloader replacement. "
        "Separate observations, likely causes, and commands. Require explicit human confirmation before any change."
    )
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": f"Knowledge:\n{load_knowledge()}\n\nReport:\n{report_text(report)}\n\nQuestion:\n{prompt}"},
        ],
    }
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.loads(response.read().decode())
        message = data.get("message", {}).get("content") or data.get("response")
        return message or json.dumps(data, indent=2)
    except Exception as exc:
        return f"Local model request failed: {exc}. The deterministic report remains available."


def require_change_confirmation(description: str, command: list[str], yes: bool) -> None:
    print(f"Planned change: {description}")
    print("Command: " + shlex.join(command))
    if not is_root():
        raise SystemExit("This operation requires root. Re-run as root after reviewing the command.")
    if not yes:
        raise SystemExit("No change made. Re-run with --yes only after reviewing the exact command.")


def valid_bootnum(value: str) -> str:
    value = value.upper().replace("BOOT", "")
    if not re.fullmatch(r"[0-9A-F]{1,4}", value):
        raise argparse.ArgumentTypeError("boot number must be hexadecimal, e.g. 0007")
    return value.zfill(4)


def valid_package(value: str) -> str:
    if not PACKAGE_RE.fullmatch(value) or value.startswith("-"):
        raise argparse.ArgumentTypeError(f"unsafe APK package name: {value!r}")
    return value


def valid_service(value: str) -> str:
    if not SERVICE_RE.fullmatch(value) or value.startswith("-"):
        raise argparse.ArgumentTypeError(f"unsafe service name: {value!r}")
    return value


def valid_interface(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,32}", value) or value.startswith("-"):
        raise argparse.ArgumentTypeError(f"unsafe network interface name: {value!r}")
    return value


def safe_firewall_path(raw: str) -> Path:
    path = Path(os.path.expandvars(os.path.expanduser(raw)))
    if path.is_symlink():
        raise SystemExit(f"Refusing to modify a symlink: {path}")
    resolved = path.resolve()
    roots = (Path("/etc"), Path("/usr/local/etc"), Path("/var/lib/alpine-maintenance-agent"), Path("/root"), Path("/home"), Path("/tmp"))
    if not any(resolved == root or root in resolved.parents for root in roots):
        raise SystemExit(f"Refusing firewall path outside approved roots: {resolved}")
    if path.exists() and not path.is_file():
        raise SystemExit(f"Refusing non-regular firewall file: {path}")
    return path


def safe_source_path(raw: str) -> Path:
    path = Path(os.path.expandvars(os.path.expanduser(raw)))
    if path.is_symlink() or not path.exists() or not path.is_file():
        raise SystemExit(f"Source file must be an existing regular file and not a symlink: {path}")
    resolved = path.resolve()
    roots = (Path("/etc"), Path("/usr/local/etc"), Path("/root"), Path("/home"), Path("/tmp"))
    if not any(resolved == root or root in resolved.parents for root in roots):
        raise SystemExit(f"Refusing source path outside approved roots: {resolved}")
    return path


def safe_config_path(raw: str) -> Path:
    path = Path(os.path.expandvars(os.path.expanduser(raw)))
    if path.is_symlink():
        raise SystemExit(f"Refusing to modify a symlink: {path}")
    resolved = path.resolve()
    if not any(resolved == root or root in resolved.parents for root in CONFIG_ROOTS):
        raise SystemExit(f"Refusing path outside approved configuration roots: {resolved}")
    if path.exists() and not path.is_file():
        raise SystemExit(f"Refusing non-regular configuration path: {path}")
    return path


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = BACKUP_DIR / f"{stamp}-{path.name}.bak"
    shutil.copy2(path, destination)
    return destination


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def get_home(args: argparse.Namespace) -> Path:
    raw = args.home or os.environ.get("ALPINE_AGENT_HOME") or os.path.expanduser("~")
    home = Path(raw).expanduser().resolve()
    if not any(home == root or root in home.parents for root in (Path("/root"), Path("/home"))):
        raise SystemExit(f"Refusing home directory outside /root or /home: {home}")
    if not home.exists() or not home.is_dir():
        raise SystemExit(f"Home directory does not exist: {home}")
    return home


def update_shell_shortcut(path: Path, alias_name: str, command: str) -> None:
    old = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    pattern = re.compile(rf"^alias\s+{re.escape(alias_name)}=.*(?:\n|$)", re.MULTILINE)
    new_line = f"alias {alias_name}={shlex.quote(command)}\n"
    updated = pattern.sub("", old)
    if updated and not updated.endswith("\n"):
        updated += "\n"
    if not updated:
        updated = "# Shortcuts managed by alpine-maintenance-agent\n"
    updated += new_line
    atomic_write(path, updated)


def remove_shell_shortcut(path: Path, alias_name: str) -> None:
    if not path.exists():
        return
    old = path.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(rf"^alias\s+{re.escape(alias_name)}=.*(?:\n|$)", re.MULTILINE)
    atomic_write(path, pattern.sub("", old))


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return slug or "application"


def desktop_content(name: str, command: str, comment: str, terminal: bool, categories: str) -> str:
    for value in (name, command, comment, categories):
        if "\n" in value or "\r" in value:
            raise SystemExit("Desktop-entry fields must not contain newlines.")
    return "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Version=1.0",
        f"Name={name}",
        f"Comment={comment}",
        f"Exec={command}",
        f"Terminal={'true' if terminal else 'false'}",
        f"Categories={categories};",
        "",
    ])


def config_env_content(path: Path, key: str, value: str) -> str:
    old = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    lines = old.splitlines()
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    replaced = False
    output: list[str] = []
    for line in lines:
        if pattern.match(line):
            if not replaced:
                output.append(f"{key}={value}")
                replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{key}={value}")
    return "\n".join(output) + "\n"


def config_ini_content(path: Path, section: str, key: str, value: str) -> str:
    parser = configparser.ConfigParser()
    parser.optionxform = str
    if path.exists():
        try:
            parser.read(path, encoding="utf-8")
        except configparser.Error as exc:
            raise SystemExit(f"Cannot parse INI file {path}: {exc}") from exc
    if not parser.has_section(section):
        parser.add_section(section)
    parser.set(section, key, value)
    output = tempfile.SpooledTemporaryFile(mode="w+", encoding="utf-8")
    parser.write(output)
    output.seek(0)
    content = output.read()
    output.close()
    return content


def installed_kernel_packages() -> list[str]:
    if not have("apk"):
        return []
    result = run(["apk", "info"])
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip().startswith("linux-")})


def current_kernel_flavor() -> str:
    release = run(["uname", "-r"]).stdout
    for flavor in ("lts", "virt", "rpi", "edge", "vanilla", "hardened"):
        if f"-{flavor}" in release or release.endswith(flavor):
            return flavor
    return ""


CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def valid_container(value: str) -> str:
    if not CONTAINER_RE.fullmatch(value) or value.startswith("-"):
        raise argparse.ArgumentTypeError(f"unsafe Docker container name or ID: {value!r}")
    return value


def docker_access() -> CommandResult:
    if not have("docker"):
        return CommandResult(["docker", "info"], 127, "", "docker is not installed")
    return run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)


def require_docker_change_confirmation(description: str, command: list[str], yes: bool) -> None:
    print(f"Planned Docker change: {description}")
    print("Command: " + shlex.join(command))
    if not have("docker"):
        raise SystemExit("docker is not installed. Install Docker and its OpenRC service first.")
    access = docker_access()
    if access.returncode != 0:
        raise SystemExit("Docker daemon is unavailable or the current user cannot access its socket. Start the service or use an authorized Docker group/root session.")
    if not yes:
        raise SystemExit("No Docker change made. Re-run with --yes only after reviewing the exact container and command.")


def docker_containers(args: argparse.Namespace, *, exact_one: bool = False) -> list[str]:
    values = [valid_container(value) for value in (args.containers or [])]
    if exact_one and len(values) != 1:
        raise SystemExit("This Docker action requires exactly one --container NAME_OR_ID")
    if not exact_one and not values:
        raise SystemExit("This Docker action requires at least one --container NAME_OR_ID")
    return values


def parse_loadavg() -> dict[str, float | int]:
    raw = read_text("/proc/loadavg", 200).split()
    values: dict[str, float | int] = {}
    for name, value in zip(("one", "five", "fifteen"), raw[:3]):
        try:
            values[name] = float(value)
        except ValueError:
            pass
    try:
        values["running_processes"] = int(raw[3].split("/", 1)[0])
        values["total_processes"] = int(raw[3].split("/", 1)[1])
    except (IndexError, ValueError):
        pass
    return values


def parse_uptime() -> float | None:
    try:
        return float(read_text("/proc/uptime", 100).split()[0])
    except (IndexError, ValueError):
        return None


def filesystem_usage() -> list[dict[str, Any]]:
    result = run(["df", "-P", "-k"], timeout=30)
    if result.returncode != 0:
        return [{"error": result.stderr or result.stdout or "df failed"}]
    filesystems: list[dict[str, Any]] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6 or not fields[4].endswith("%"):
            continue
        try:
            use_percent = int(fields[4][:-1])
            total_kb = int(fields[1])
            used_kb = int(fields[2])
            available_kb = int(fields[3])
        except ValueError:
            continue
        filesystems.append({
            "filesystem": fields[0],
            "total_kb": total_kb,
            "used_kb": used_kb,
            "available_kb": available_kb,
            "use_percent": use_percent,
            "mountpoint": " ".join(fields[5:]),
        })
    return filesystems


def network_counters() -> dict[str, dict[str, int]]:
    counters: dict[str, dict[str, int]] = {}
    raw = read_text("/proc/net/dev", 20000)
    for line in raw.splitlines():
        if ":" not in line:
            continue
        interface, values = line.split(":", 1)
        interface = interface.strip()
        fields = values.split()
        if len(fields) < 9:
            continue
        try:
            counters[interface] = {
                "rx_bytes": int(fields[0]),
                "rx_packets": int(fields[1]),
                "tx_bytes": int(fields[8]),
                "tx_packets": int(fields[9]),
            }
        except (IndexError, ValueError):
            continue
    return counters


def process_snapshot(limit: int) -> dict[str, Any]:
    if not have("ps"):
        return {"available": False, "reason": "ps is unavailable"}
    result = run(["ps", "-eo", "pid,comm,%cpu,%mem,rss", "--sort=-%cpu"], timeout=20)
    if result.returncode != 0:
        result = run(["ps"], timeout=20)
    lines = result.stdout.splitlines()
    return {"available": result.returncode == 0, "output": "\n".join(lines[: max(2, limit + 1)]), "error": result.stderr}


def docker_stats_snapshot() -> dict[str, Any]:
    access = docker_access()
    if access.returncode != 0:
        return {"available": False, "reason": access.stderr or access.stdout or "Docker daemon unavailable"}
    command = ["docker", "container", "stats", "--all", "--no-stream", "--format", "{{json .}}"]
    result = run(command, timeout=60)
    if result.returncode != 0:
        return {"available": False, "reason": result.stderr or result.stdout or "docker stats failed"}
    rows: list[Any] = []
    for line in result.stdout.splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append({"raw": line})
    return {"available": True, "containers": rows}


def collect_resource_report(*, include_docker: bool = False, top: int = 5, memory_warn: int = 10, disk_warn: int = 90, load_warn: float = 1.0) -> dict[str, Any]:
    mem = parse_meminfo()
    total_kb = mem.get("MemTotal", 0)
    available_kb = mem.get("MemAvailable", mem.get("MemFree", 0))
    swap_total_kb = mem.get("SwapTotal", 0)
    swap_free_kb = mem.get("SwapFree", 0)
    filesystems = filesystem_usage()
    loadavg = parse_loadavg()
    cpu_count = os.cpu_count() or 1
    report: dict[str, Any] = {
        "agent": APP_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": run(["hostname"], timeout=5).stdout or "unknown",
        "cpu_count": cpu_count,
        "load_average": loadavg,
        "uptime_seconds": parse_uptime(),
        "memory": {
            "total_kb": total_kb,
            "available_kb": available_kb,
            "available_percent": round(100 * available_kb / total_kb, 1) if total_kb else None,
            "swap_total_kb": swap_total_kb,
            "swap_free_kb": swap_free_kb,
        },
        "filesystems": filesystems,
        "network": network_counters(),
        "processes": process_snapshot(max(1, min(top, 50))),
        "warnings": [],
        "safe_mode": True,
    }
    warnings: list[str] = report["warnings"]
    available_percent = report["memory"].get("available_percent")
    if available_percent is not None and available_percent < memory_warn:
        warnings.append(f"available memory is {available_percent}% (< {memory_warn}%)")
    for filesystem in filesystems:
        if filesystem.get("use_percent", 0) >= disk_warn:
            warnings.append(f"{filesystem.get('mountpoint', 'unknown')} is {filesystem.get('use_percent')}% full")
    load_one = loadavg.get("one")
    if isinstance(load_one, float) and load_one > cpu_count * load_warn:
        warnings.append(f"1-minute load average {load_one:.2f} exceeds {load_warn:.2f} per CPU")
    if include_docker:
        report["docker"] = docker_stats_snapshot()
    return report


def resource_report_text(report: dict[str, Any]) -> str:
    memory = report.get("memory", {})
    loadavg = report.get("load_average", {})
    lines = [
        f"Resource report — {report.get('timestamp', 'unknown')}",
        f"Host: {report.get('hostname', 'unknown')}",
        f"CPU count: {report.get('cpu_count', 'unknown')}",
        f"Load average: {loadavg.get('one', '?')} {loadavg.get('five', '?')} {loadavg.get('fifteen', '?')}",
        f"Memory available: {memory.get('available_percent', '?')}% ({memory.get('available_kb', '?')} kB)",
        f"Swap free: {memory.get('swap_free_kb', '?')} / {memory.get('swap_total_kb', '?')} kB",
        "",
        "Filesystems:",
    ]
    for item in report.get("filesystems", []):
        if "error" in item:
            lines.append(f"  {item['error']}")
        else:
            lines.append(f"  {item['mountpoint']}: {item['use_percent']}% used, {item['available_kb']} kB available")
    processes = report.get("processes", {})
    if processes.get("output"):
        lines.extend(["", "Top process snapshot:", textwrap.indent(processes["output"], "  ")])
    docker = report.get("docker")
    if docker is not None:
        lines.extend(["", "Docker stats:", json.dumps(docker, indent=2)])
    warnings = report.get("warnings", [])
    lines.extend(["", f"Warnings: {len(warnings)}"])
    for warning in warnings:
        lines.append(f"  WARN: {warning}")
    return "\n".join(lines)


def firewall_tools(family: str) -> tuple[str, str, str]:
    if family == "ipv4":
        return "iptables", "iptables-save", "iptables-restore"
    if family == "ipv6":
        return "ip6tables", "ip6tables-save", "ip6tables-restore"
    raise SystemExit(f"Unsupported firewall family: {family}")


def firewall_snapshot(family: str) -> Path | None:
    _, save_tool, _ = firewall_tools(family)
    if not have(save_tool):
        return None
    destination_dir = BACKUP_DIR / "firewall"
    destination_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = destination_dir / f"{stamp}-{family}.rules"
    result = run([save_tool, "-f", str(destination)], timeout=60)
    if result.returncode != 0:
        return None
    return destination


def firewall_file_has_drop_policy(content: str) -> bool:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if re.search(r"^-P\s+(INPUT|FORWARD)\s+DROP(?:\s|$)", line):
            return True
        if re.search(r"^:(INPUT|FORWARD)\s+DROP(?:\s|$)", line):
            return True
    return False


def validate_firewall_rules(family: str, content: str) -> CommandResult:
    _, _, restore_tool = firewall_tools(family)
    if not have(restore_tool):
        return CommandResult([restore_tool, "--test"], 127, "", f"command not found: {restore_tool}")
    return run_with_input([restore_tool, "--test"], content, timeout=60)


def network_interface_exists(interface: str) -> bool:
    return Path("/sys/class/net").joinpath(interface).exists()


def do_action(args: argparse.Namespace) -> int:
    action = args.action
    result: CommandResult | None = None

    if action == "mount-efivarfs":
        command = ["mount", "-t", "efivarfs", "efivarfs", "/sys/firmware/efi/efivars"]
        if is_mounted("/sys/firmware/efi/efivars"):
            print("efivarfs is already mounted; no change needed.")
            return 0
        require_change_confirmation("mount EFI variable filesystem", command, args.yes)
        result = run(command)

    elif action == "install-efibootmgr":
        command = ["apk", "add", "efibootmgr"]
        require_change_confirmation("install efibootmgr from the configured APK repositories", command, args.yes)
        result = run(command, timeout=120)

    elif action == "activate-entry":
        bootnum = valid_bootnum(args.bootnum)
        command = ["efibootmgr", "-a", "-b", bootnum]
        require_change_confirmation(f"activate EFI boot entry Boot{bootnum}", command, args.yes)
        result = run(command)

    elif action == "set-bootnext":
        bootnum = valid_bootnum(args.bootnum)
        command = ["efibootmgr", "-n", bootnum]
        require_change_confirmation(f"set BootNext to Boot{bootnum} for one boot", command, args.yes)
        result = run(command)

    elif action == "cancel-bootnext":
        command = ["efibootmgr", "-N"]
        require_change_confirmation("clear the pending one-time boot request", command, args.yes)
        result = run(command)

    elif action == "create-efi-entry":
        command = ["efibootmgr", "-c", "-d", args.disk, "-p", str(args.part), "-L", args.label, "-l", args.loader, "--unicode"]
        require_change_confirmation(f"create EFI entry {args.label!r} on {args.disk} partition {args.part}", command, args.yes)
        result = run(command)

    elif action in {"apk-update", "apk-upgrade"}:
        command = ["apk", "update"] if action == "apk-update" else ["apk", "upgrade"]
        require_change_confirmation("refresh APK indexes" if action == "apk-update" else "upgrade all installed Alpine packages", command, args.yes)
        backup_file(Path("/etc/apk/world"))
        result = run(command, timeout=600 if action == "apk-upgrade" else 180)

    elif action in {"package-install", "package-uninstall", "package-upgrade"}:
        packages = [valid_package(item) for item in (args.packages or [])]
        if not packages:
            raise SystemExit(f"{action} requires at least one --package NAME")
        if action == "package-install":
            command = ["apk", "add", *packages]
            description = f"install package(s): {', '.join(packages)}"
        elif action == "package-upgrade":
            command = ["apk", "add", "--upgrade", *packages]
            description = f"upgrade selected package(s): {', '.join(packages)}"
        else:
            blocked = [pkg for pkg in packages if pkg in PROTECTED_PACKAGES or pkg.startswith("linux-")]
            if blocked:
                raise SystemExit(f"Refusing package uninstall for protected/kernel package(s): {', '.join(blocked)}. Use kernel-remove only for a non-running spare kernel.")
            command = ["apk", "del", *packages]
            description = f"uninstall package(s): {', '.join(packages)}"
        require_change_confirmation(description, command, args.yes)
        backup_file(Path("/etc/apk/world"))
        result = run(command, timeout=600)

    elif action == "kernel-list":
        running = run(["uname", "-r"]).stdout or "unavailable"
        files = sorted(str(item) for item in Path("/boot").glob("*")) if Path("/boot").exists() else []
        print(f"Running kernel: {running}")
        print("Installed kernel packages:")
        print("\n".join(installed_kernel_packages()) or "  none detected")
        print("/boot files:")
        print("\n".join(files) or "  unavailable")
        return 0

    elif action == "kernel-update":
        packages = [valid_package(item) for item in (args.packages or [])]
        if len(packages) != 1 or not packages[0].startswith("linux-"):
            raise SystemExit("kernel-update requires exactly one kernel package, for example --package linux-lts")
        package = packages[0]
        command = ["apk", "add", "--upgrade", package]
        require_change_confirmation(f"update kernel package {package}; reboot will remain manual", command, args.yes)
        backup_file(Path("/etc/apk/world"))
        result = run(command, timeout=600)
        if result.returncode == 0:
            print("Kernel package update completed. Inspect /boot and reboot manually after reviewing the new entry.")

    elif action == "kernel-remove":
        packages = [valid_package(item) for item in (args.packages or [])]
        if len(packages) != 1 or not packages[0].startswith("linux-"):
            raise SystemExit("kernel-remove requires exactly one kernel package, for example --package linux-lts")
        package = packages[0]
        flavor = current_kernel_flavor()
        if flavor and package == f"linux-{flavor}":
            raise SystemExit(f"Refusing to remove the currently running kernel flavor: {package}")
        installed = installed_kernel_packages()
        if len(installed) <= 1:
            raise SystemExit("Refusing to remove the last detected installed kernel package.")
        command = ["apk", "del", package]
        require_change_confirmation(f"remove non-running kernel package {package}", command, args.yes)
        backup_file(Path("/etc/apk/world"))
        result = run(command, timeout=600)

    elif action in {"service-enable", "service-disable"}:
        service = valid_service(args.service)
        command = ["rc-update", "add", service, "default"] if action == "service-enable" else ["rc-update", "del", service, "default"]
        require_change_confirmation(f"{'enable' if action == 'service-enable' else 'disable'} OpenRC service {service}", command, args.yes)
        result = run(command)

    elif action == "docker-info":
        if not have("docker"):
            raise SystemExit("docker is not installed. Install Docker before using Docker actions.")
        outputs = []
        for command in (["docker", "info"], ["docker", "version"], ["docker", "container", "ls", "--all", "--no-trunc"]):
            inspected = run(command, timeout=60)
            outputs.append(f"$ {shlex.join(command)}\n{inspected.stdout or inspected.stderr}")
        print("\n\n".join(outputs))
        return 0

    elif action == "docker-list":
        if not have("docker"):
            raise SystemExit("docker is not installed. Install Docker before using Docker actions.")
        command = ["docker", "container", "ls", "--all", "--no-trunc"]
        result = run(command, timeout=60)

    elif action == "docker-inspect":
        containers = docker_containers(args, exact_one=True)
        result = run(["docker", "container", "inspect", *containers], timeout=60)

    elif action == "docker-logs":
        containers = docker_containers(args, exact_one=True)
        if not re.fullmatch(r"[0-9]+", args.tail or "") or int(args.tail) > 10000:
            raise SystemExit("docker-logs requires --tail as a number from 0 through 10000")
        command = ["docker", "container", "logs", "--tail", args.tail]
        if args.timestamps:
            command.append("--timestamps")
        if args.since:
            if "\n" in args.since or "\r" in args.since:
                raise SystemExit("--since must not contain newlines")
            command.extend(["--since", args.since])
        if args.until:
            if "\n" in args.until or "\r" in args.until:
                raise SystemExit("--until must not contain newlines")
            command.extend(["--until", args.until])
        result = run([*command, containers[0]], timeout=60)

    elif action == "docker-top":
        containers = docker_containers(args, exact_one=True)
        result = run(["docker", "container", "top", containers[0]], timeout=60)

    elif action == "docker-stats":
        if not have("docker"):
            raise SystemExit("docker is not installed. Install Docker before using Docker actions.")
        containers = [valid_container(value) for value in (args.containers or [])]
        command = ["docker", "container", "stats", "--all", "--no-stream"]
        if args.json:
            command.extend(["--format", "{{json .}}"])
        result = run([*command, *containers], timeout=90)

    elif action in {"docker-start", "docker-stop", "docker-restart", "docker-pause", "docker-unpause"}:
        containers = docker_containers(args)
        subcommand = action.removeprefix("docker-")
        command = ["docker", "container", subcommand]
        if subcommand in {"stop", "restart"}:
            timeout_value = args.timeout
            if timeout_value is not None:
                if timeout_value < 0 or timeout_value > 86400:
                    raise SystemExit("--timeout must be between 0 and 86400 seconds")
                command.extend(["--time", str(timeout_value)])
        command.extend(containers)
        require_docker_change_confirmation(f"{subcommand} container(s): {', '.join(containers)}", command, args.yes)
        result = run(command, timeout=max(60, (args.timeout or 10) + 30))

    elif action == "docker-service-status":
        if not have("rc-service"):
            raise SystemExit("rc-service is unavailable; this does not appear to be an OpenRC system.")
        result = run(["rc-service", "docker", "status"], timeout=30)

    elif action in {"docker-service-start", "docker-service-stop", "docker-service-restart"}:
        if not have("rc-service"):
            raise SystemExit("rc-service is unavailable; this does not appear to be an OpenRC system.")
        verb = action.removeprefix("docker-service-")
        command = ["rc-service", "docker", verb]
        require_change_confirmation(f"{verb} the Docker OpenRC service", command, args.yes)
        result = run(command, timeout=120)

    elif action in {"docker-service-enable", "docker-service-disable"}:
        if not have("rc-update"):
            raise SystemExit("rc-update is unavailable; this does not appear to be an OpenRC system.")
        verb = "add" if action.endswith("enable") else "del"
        command = ["rc-update", verb, "docker", "default"]
        require_change_confirmation(f"{verb} Docker in the OpenRC default runlevel", command, args.yes)
        result = run(command, timeout=60)

    elif action == "resource-report":
        report = collect_resource_report(
            include_docker=args.with_docker,
            top=args.top,
            memory_warn=args.memory_warn,
            disk_warn=args.disk_warn,
            load_warn=args.load_warn,
        )
        result = CommandResult(["resource-report"], 0, json.dumps(report, indent=2) if args.json else resource_report_text(report), "")

    elif action == "resource-watch":
        if args.duration < 1 or args.duration > 86400:
            raise SystemExit("resource-watch duration must be between 1 and 86400 seconds")
        if args.interval < 1 or args.interval > 3600:
            raise SystemExit("resource-watch interval must be between 1 and 3600 seconds")
        deadline = time.monotonic() + args.duration
        samples = 0
        while True:
            report = collect_resource_report(
                include_docker=args.with_docker,
                top=args.top,
                memory_warn=args.memory_warn,
                disk_warn=args.disk_warn,
                load_warn=args.load_warn,
            )
            samples += 1
            print(json.dumps(report, separators=(",", ":")) if args.json else resource_report_text(report))
            if time.monotonic() + args.interval > deadline:
                break
            time.sleep(args.interval)
        append_audit("resource-watch", f"completed {samples} read-only sample(s)")
        return 0

    elif action == "network-show":
        if not have("ip"):
            raise SystemExit("The ip command is unavailable. Install iproute2 first.")
        outputs = []
        for command in (["ip", "-brief", "link"], ["ip", "-brief", "address"], ["ip", "route"]):
            inspected = run(command)
            outputs.append(f"$ {shlex.join(command)}\n{inspected.stdout or inspected.stderr}")
        print("\n\n".join(outputs))
        return 0

    elif action == "network-config-show":
        path = safe_config_path(args.file or "/etc/network/interfaces")
        print(read_text(path))
        return 0

    elif action in {"interface-up", "interface-down", "interface-restart"}:
        interface = valid_interface(args.interface)
        if not network_interface_exists(interface):
            raise SystemExit(f"Network interface does not exist: {interface}")
        if action == "interface-up":
            command = ["ip", "link", "set", "dev", interface, "up"]
            description = f"bring interface {interface} up"
        elif action == "interface-down":
            command = ["ip", "link", "set", "dev", interface, "down"]
            description = f"bring interface {interface} down"
        else:
            if not have("ifdown") or not have("ifup"):
                raise SystemExit("interface-restart requires ifdown and ifup; use network-service-restart if the interface is managed by OpenRC")
            command = ["ifdown", interface, "&&", "ifup", interface]
            description = f"restart interface {interface} using ifdown/ifup"
        require_change_confirmation(description, command, args.yes)
        if action == "interface-restart":
            down_result = run(["ifdown", interface], timeout=60)
            if down_result.returncode != 0:
                result = down_result
            else:
                up_result = run(["ifup", interface], timeout=60)
                result = CommandResult(["ifdown", interface, "then", "ifup", interface], up_result.returncode, up_result.stdout, down_result.stderr + ("\n" + up_result.stderr if up_result.stderr else ""))
        else:
            result = run(command, timeout=60)

    elif action == "network-config-install":
        source = safe_source_path(args.source)
        destination = safe_config_path(args.file or "/etc/network/interfaces")
        content = source.read_text(encoding="utf-8", errors="replace")
        if "\x00" in content:
            raise SystemExit("Refusing a network configuration containing NUL bytes")
        require_change_confirmation(f"install network configuration from {source} to {destination}; networking will not be restarted automatically", ["install-network-config", str(source), str(destination)], args.yes)
        backup_file(destination)
        atomic_write(destination, content)
        result = CommandResult(["install-network-config", str(destination)], 0, f"Installed {destination}. Review it, then restart networking manually if appropriate.", "")

    elif action in {"network-service-restart", "network-service-enable", "network-service-disable"}:
        if action == "network-service-restart":
            command = ["rc-service", "networking", "restart"]
            description = "restart the OpenRC networking service; the active connection may drop"
        elif action == "network-service-enable":
            command = ["rc-update", "add", "networking", "boot"]
            description = "enable the OpenRC networking service at boot"
        else:
            command = ["rc-update", "del", "networking", "boot"]
            description = "disable the OpenRC networking service at boot"
        require_change_confirmation(description, command, args.yes)
        result = run(command, timeout=120)

    elif action == "firewall-show":
        tool, _, _ = firewall_tools(args.family)
        if not have(tool):
            raise SystemExit(f"{tool} is unavailable. Install the Alpine iptables package first.")
        result = run([tool, "-S"], timeout=60)

    elif action == "firewall-validate":
        source = safe_source_path(args.file)
        content = source.read_text(encoding="utf-8", errors="replace")
        result = validate_firewall_rules(args.family, content)
        if result.returncode == 0:
            result = CommandResult(result.command, 0, f"{source} is valid for {args.family}.", result.stderr)

    elif action == "firewall-save":
        _, save_tool, _ = firewall_tools(args.family)
        if not have(save_tool):
            raise SystemExit(f"{save_tool} is unavailable. Install the Alpine iptables package first.")
        if args.file:
            destination = safe_firewall_path(args.file)
        else:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            destination = safe_firewall_path(str(BACKUP_DIR / "firewall" / f"{stamp}-{args.family}.rules"))
        command = [save_tool, "-f", str(destination)]
        require_change_confirmation(f"save the current {args.family} firewall rules to {destination}", command, args.yes)
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = run(command, timeout=60)

    elif action in {"firewall-apply", "firewall-restore"}:
        source = safe_source_path(args.file)
        content = source.read_text(encoding="utf-8", errors="replace")
        validation = validate_firewall_rules(args.family, content)
        if validation.returncode != 0:
            raise SystemExit(f"Firewall validation failed; no rules were changed.\n{validation.stderr or validation.stdout}")
        if firewall_file_has_drop_policy(content) and not args.allow_drop:
            raise SystemExit("Refusing a ruleset with INPUT/FORWARD DROP policy unless --allow-drop is explicitly supplied. This can disconnect SSH or other remote administration.")
        _, _, restore_tool = firewall_tools(args.family)
        mode = "apply" if action == "firewall-apply" else "restore"
        command = [restore_tool, "<", str(source)]
        require_change_confirmation(f"{mode} validated {args.family} firewall rules from {source}; current rules will be backed up first", command, args.yes)
        backup = firewall_snapshot(args.family)
        if backup is None:
            raise SystemExit("Could not create a current firewall backup; no rules were changed.")
        result = run_with_input([restore_tool], content, timeout=60)
        if result.returncode == 0:
            result = CommandResult(result.command, 0, f"Applied {args.family} rules. Rollback source: {backup}", result.stderr)

    elif action == "firewall-openrc-enable":
        service = "iptables" if args.family == "ipv4" else "ip6tables"
        command = ["rc-update", "add", service, "default"]
        require_change_confirmation(f"enable the {service} OpenRC firewall service at boot", command, args.yes)
        result = run(command)

    elif action == "firewall-openrc-save":
        service = "iptables" if args.family == "ipv4" else "ip6tables"
        command = ["rc-service", service, "save"]
        require_change_confirmation(f"save the current {args.family} rules through OpenRC service {service}", command, args.yes)
        result = run(command, timeout=60)

    elif action == "package-search":
        if not args.query or "\n" in args.query or "\r" in args.query:
            raise SystemExit("package-search requires a non-empty --query without newlines")
        result = run(["apk", "search", "-v", args.query], timeout=60)

    elif action == "package-info":
        package_values = args.packages or []
        if len(package_values) != 1:
            raise SystemExit("package-info requires exactly one --package NAME")
        package = valid_package(package_values[0])
        result = run(["apk", "info", "-a", package], timeout=60)

    elif action == "config-show":
        path = safe_config_path(args.file)
        print(read_text(path))
        return 0

    elif action == "config-set":
        path = safe_config_path(args.file)
        key = args.key
        value = args.value
        if not KEY_RE.fullmatch(key) or "\n" in value or "\r" in value:
            raise SystemExit("config-set requires a safe key and a value without newlines")
        if args.format == "ini":
            if not args.section or not KEY_RE.fullmatch(args.section):
                raise SystemExit("INI configuration requires --section SECTION")
            content = config_ini_content(path, args.section, key, value)
        else:
            content = config_env_content(path, key, value)
        require_change_confirmation(f"update {args.format} configuration key {key} in {path}", ["write-config", str(path), "--key", key], args.yes)
        backup_file(path)
        atomic_write(path, content)
        result = CommandResult(["write-config", str(path)], 0, f"Updated {path}", "")

    elif action == "shortcut-add":
        name = args.name
        command_text = args.command_text
        if not ALIAS_RE.fullmatch(name) or "\n" in command_text or "\r" in command_text:
            raise SystemExit("shortcut-add requires a safe alias name and a command without newlines")
        path = safe_config_path(str(get_home(args) / ".config/alpine-agent/shortcuts.sh"))
        require_change_confirmation(f"write shell shortcut {name} to {path}", ["write-shortcut", str(path), "--alias", name], args.yes)
        backup_file(path)
        update_shell_shortcut(path, name, command_text)
        result = CommandResult(["write-shortcut", str(path)], 0, f"Shortcut {name} updated. Source it with: . {path}", "")

    elif action == "shortcut-remove":
        name = args.name
        if not ALIAS_RE.fullmatch(name):
            raise SystemExit("shortcut-remove requires a safe alias name")
        path = safe_config_path(str(get_home(args) / ".config/alpine-agent/shortcuts.sh"))
        require_change_confirmation(f"remove shell shortcut {name} from {path}", ["remove-shortcut", str(path), "--alias", name], args.yes)
        backup_file(path)
        remove_shell_shortcut(path, name)
        result = CommandResult(["remove-shortcut", str(path)], 0, f"Shortcut {name} removed.", "")

    elif action == "desktop-entry-create":
        name = args.name
        if not SAFE_NAME_RE.fullmatch(name) or "\n" in args.exec_command or "\r" in args.exec_command:
            raise SystemExit("desktop-entry-create requires a safe name and an Exec value without newlines")
        home = get_home(args)
        raw_path = args.desktop_file or str(home / ".local/share/applications" / f"{slugify(name)}.desktop")
        path = safe_config_path(raw_path)
        content = desktop_content(name, args.exec_command, args.comment, args.terminal, args.categories)
        require_change_confirmation(f"create desktop launcher {path}", ["write-desktop-entry", str(path)], args.yes)
        backup_file(path)
        atomic_write(path, content)
        result = CommandResult(["write-desktop-entry", str(path)], 0, f"Desktop launcher written to {path}", "")

    elif action == "desktop-entry-remove":
        path = safe_config_path(args.desktop_file)
        if path.suffix != ".desktop":
            raise SystemExit("desktop-entry-remove requires a .desktop file")
        require_change_confirmation(f"remove desktop launcher {path}", ["remove-desktop-entry", str(path)], args.yes)
        backup_file(path)
        if path.exists():
            path.unlink()
        result = CommandResult(["remove-desktop-entry", str(path)], 0, f"Desktop launcher removed: {path}", "")

    else:
        raise SystemExit(f"Unknown action: {action}")

    if result is None:
        return 1
    append_audit(action, result.stdout or result.stderr)
    print(result.stdout or result.stderr)
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Conservative local Alpine Linux maintenance assistant")
    parser.add_argument("--efi-part", help="EFI partition to inspect read-only, for example /dev/sda1")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="run read-only health and EFI diagnostics")
    doctor.add_argument("--json", action="store_true", help="emit JSON instead of human-readable output")

    ask = sub.add_parser("ask", help="ask an optional local model using the current report and knowledge")
    ask.add_argument("question", nargs="+", help="question for the local assistant")

    sub.add_parser("knowledge", help="print the embedded maintenance knowledge")
    sub.add_parser("audit", help="show the local audit log")

    action_choices = [
        "mount-efivarfs", "install-efibootmgr", "activate-entry", "set-bootnext", "cancel-bootnext", "create-efi-entry",
        "apk-update", "apk-upgrade", "package-install", "package-uninstall", "package-upgrade", "package-search", "package-info",
        "kernel-list", "kernel-update", "kernel-remove", "service-enable", "service-disable", "config-show", "config-set",
        "shortcut-add", "shortcut-remove", "desktop-entry-create", "desktop-entry-remove",
        "network-show", "network-config-show", "network-config-install", "interface-up", "interface-down", "interface-restart",
        "network-service-restart", "network-service-enable", "network-service-disable",
        "firewall-show", "firewall-validate", "firewall-save", "firewall-apply", "firewall-restore", "firewall-openrc-enable", "firewall-openrc-save",
        "docker-info", "docker-list", "docker-inspect", "docker-logs", "docker-top", "docker-stats",
        "docker-start", "docker-stop", "docker-restart", "docker-pause", "docker-unpause",
        "docker-service-status", "docker-service-start", "docker-service-stop", "docker-service-restart",
        "docker-service-enable", "docker-service-disable",
    ]
    action = sub.add_parser("action", help="perform an explicitly approved maintenance action")
    action.add_argument("action", choices=action_choices)
    action.add_argument("--yes", action="store_true", help="confirm the exact displayed change")
    action.add_argument("--bootnum", type=valid_bootnum, help="EFI boot number for activate-entry or set-bootnext")
    action.add_argument("--disk", help="disk for create-efi-entry, e.g. /dev/sdb")
    action.add_argument("--part", type=int, help="partition number for create-efi-entry")
    action.add_argument("--loader", default=r"\EFI\BOOT\BOOTX64.EFI", help="EFI loader path for create-efi-entry")
    action.add_argument("--label", default="Alpine agent entry", help="EFI label for create-efi-entry")
    action.add_argument("--package", dest="packages", action="append", help="APK package name; repeat for multiple packages")
    action.add_argument("--query", help="APK search query")
    action.add_argument("--service", help="OpenRC service name")
    action.add_argument("--interface", type=valid_interface, help="network interface name")
    action.add_argument("--family", choices=["ipv4", "ipv6"], default="ipv4", help="firewall address family")
    action.add_argument("--source", help="existing source file for network configuration")
    action.add_argument("--allow-drop", action="store_true", help="allow INPUT/FORWARD DROP policy after explicit review")
    action.add_argument("--file", help="approved configuration or firewall file path")
    action.add_argument("--format", choices=["env", "ini"], default="env", help="configuration file format")
    action.add_argument("--section", help="INI section")
    action.add_argument("--key", help="configuration key")
    action.add_argument("--value", help="configuration value")
    action.add_argument("--home", help="target user home under /root or /home")
    action.add_argument("--name", help="shortcut or desktop launcher name")
    action.add_argument("--command", dest="command_text", help="shell command for a shortcut")
    action.add_argument("--exec", dest="exec_command", help="Exec command for a desktop launcher")
    action.add_argument("--comment", default="Managed by Alpine Maintenance Agent", help="desktop launcher comment")
    action.add_argument("--categories", default="Utility", help="desktop launcher categories")
    action.add_argument("--terminal", action="store_true", help="run desktop launcher in a terminal")
    action.add_argument("--desktop-file", help="desktop launcher file path")
    action.add_argument("--container", dest="containers", action="append", type=valid_container, help="Docker container name or ID; repeat for multiple containers")
    action.add_argument("--tail", default="200", help="Docker log line count, from 0 through 10000")
    action.add_argument("--since", help="Docker log time filter")
    action.add_argument("--until", help="Docker log time filter")
    action.add_argument("--timestamps", action="store_true", help="include timestamps in Docker logs")
    action.add_argument("--timeout", type=int, default=10, help="Docker stop/restart timeout in seconds")
    action.add_argument("--json", action="store_true", help="emit JSON for Docker stats")

    def add_resource_options(resource_parser: argparse.ArgumentParser, *, watch: bool = False) -> None:
        resource_parser.add_argument("--json", action="store_true", help="emit JSON output")
        resource_parser.add_argument("--with-docker", action="store_true", help="include Docker container stats when Docker is available")
        resource_parser.add_argument("--top", type=int, default=5, help="number of process rows to include, from 1 through 50")
        resource_parser.add_argument("--memory-warn", type=int, default=10, help="warn below this available-memory percentage")
        resource_parser.add_argument("--disk-warn", type=int, default=90, help="warn at or above this filesystem-use percentage")
        resource_parser.add_argument("--load-warn", type=float, default=1.0, help="warn above this 1-minute load per CPU")
        if watch:
            resource_parser.add_argument("--duration", type=int, default=60, help="bounded watch duration in seconds")
            resource_parser.add_argument("--interval", type=int, default=5, help="sampling interval in seconds")

    resource_report = sub.add_parser("resource-report", help="read-only host resource report")
    add_resource_options(resource_report)
    resource_watch = sub.add_parser("resource-watch", help="bounded read-only resource monitor")
    add_resource_options(resource_watch, watch=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "doctor":
        report = collect_report(args.efi_part)
        print(json.dumps(report, indent=2) if args.json else report_text(report))
        return 0 if report["warning_count"] == 0 else 2
    if args.command == "resource-report":
        if not 1 <= args.top <= 50:
            parser.error("resource-report --top must be between 1 and 50")
        if not 0 <= args.memory_warn <= 100 or not 0 <= args.disk_warn <= 100 or args.load_warn < 0:
            parser.error("resource-report thresholds are out of range")
        report = collect_resource_report(
            include_docker=args.with_docker,
            top=args.top,
            memory_warn=args.memory_warn,
            disk_warn=args.disk_warn,
            load_warn=args.load_warn,
        )
        print(json.dumps(report, indent=2) if args.json else resource_report_text(report))
        return 0
    if args.command == "resource-watch":
        if not 1 <= args.top <= 50:
            parser.error("resource-watch --top must be between 1 and 50")
        if not 1 <= args.duration <= 86400 or not 1 <= args.interval <= 3600:
            parser.error("resource-watch duration or interval is out of range")
        if not 0 <= args.memory_warn <= 100 or not 0 <= args.disk_warn <= 100 or args.load_warn < 0:
            parser.error("resource-watch thresholds are out of range")
        deadline = time.monotonic() + args.duration
        samples = 0
        while True:
            report = collect_resource_report(
                include_docker=args.with_docker,
                top=args.top,
                memory_warn=args.memory_warn,
                disk_warn=args.disk_warn,
                load_warn=args.load_warn,
            )
            samples += 1
            print(json.dumps(report, separators=(",", ":")) if args.json else resource_report_text(report))
            if time.monotonic() + args.interval > deadline:
                break
            time.sleep(args.interval)
        append_audit("resource-watch", f"completed {samples} read-only sample(s)")
        return 0
    if args.command == "knowledge":
        print(load_knowledge())
        return 0
    if args.command == "audit":
        print(read_text(LOG_PATH) if LOG_PATH.exists() else "No audit log yet.")
        return 0
    if args.command == "ask":
        report = collect_report(args.efi_part)
        print(local_model_answer(" ".join(args.question), report))
        return 0
    if args.command == "action":
        if args.action in {"activate-entry", "set-bootnext"} and not args.bootnum:
            parser.error(f"action {args.action} requires --bootnum XXXX")
        if args.action == "create-efi-entry" and (not args.disk or not args.part):
            parser.error("create-efi-entry requires --disk /dev/... and --part N")
        if args.action in {"package-search"} and not args.query:
            parser.error("package-search requires --query TEXT")
        if args.action == "package-info" and len(args.packages or []) != 1:
            parser.error("package-info requires exactly one --package NAME")
        if args.action in {"service-enable", "service-disable"} and not args.service:
            parser.error(f"{args.action} requires --service NAME")
        if args.action in {"interface-up", "interface-down", "interface-restart"} and not args.interface:
            parser.error(f"{args.action} requires --interface NAME")
        if args.action == "network-config-install" and not args.source:
            parser.error("network-config-install requires --source PATH")
        if args.action in {"network-config-show", "firewall-validate", "firewall-apply", "firewall-restore"} and not args.file:
            parser.error(f"{args.action} requires --file PATH")
        if args.action in {"config-show"} and not args.file:
            parser.error("config-show requires --file PATH")
        if args.action == "config-set" and (not args.file or not args.key or args.value is None):
            parser.error("config-set requires --file PATH --key KEY --value VALUE")
        if args.action in {"shortcut-add", "shortcut-remove"} and not args.name:
            parser.error(f"{args.action} requires --name NAME")
        if args.action == "shortcut-add" and args.command_text is None:
            parser.error("shortcut-add requires --command COMMAND")
        if args.action == "desktop-entry-create" and (not args.name or args.exec_command is None):
            parser.error("desktop-entry-create requires --name NAME --exec COMMAND")
        if args.action == "desktop-entry-remove" and not args.desktop_file:
            parser.error("desktop-entry-remove requires --desktop-file PATH")
        return do_action(args)
    parser.error("a command is required")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
