#!/bin/sh
# Installs ~/.kps/bin/kps: a wrapper with absolute paths, for callers without your shell PATH
# (KeePassXC Remote Sync runs commands without your shell profile, so nvm/homebrew node isn't found).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NODE=$(command -v node)
BIN="${KPS_HOME:-$HOME/.kps}/bin"
mkdir -p "$BIN"
cat > "$BIN/kps" <<WRAPPER
#!/bin/sh
exec "$NODE" --disable-warning=ExperimentalWarning "$ROOT/client/cli.ts" "\$@"
WRAPPER
chmod 755 "$BIN/kps"
echo "Installed $BIN/kps (node: $NODE)"
