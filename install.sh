#!/bin/sh
set -eu

PREFIX=${PREFIX:-/usr/local}
BIN_DIR="$PREFIX/bin"
DATA_DIR="$PREFIX/share/alpine-maintenance-agent"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo sh install.sh" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required. On Alpine, install it with: apk add python3" >&2
    exit 1
fi

mkdir -p "$BIN_DIR" "$DATA_DIR"
install -m 0755 "$SCRIPT_DIR/alpine_agent.py" "$DATA_DIR/alpine_agent.py"
install -m 0644 "$SCRIPT_DIR/share/knowledge.md" "$DATA_DIR/knowledge.md"

cat > "$BIN_DIR/alpine-agent" <<EOF
#!/bin/sh
set -eu
export ALPINE_AGENT_KNOWLEDGE=\${ALPINE_AGENT_KNOWLEDGE:-$DATA_DIR/knowledge.md}
exec python3 "$DATA_DIR/alpine_agent.py" "\$@"
EOF
chmod 0755 "$BIN_DIR/alpine-agent"

cat <<EOF
Installed:
  $BIN_DIR/alpine-agent
  $DATA_DIR/alpine_agent.py
  $DATA_DIR/knowledge.md

No daemon was enabled and no EFI variables or boot files were changed.
Try:
  $BIN_DIR/alpine-agent doctor
EOF
