#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer requires a Linux user systemd session." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl was not found." >&2
  exit 1
fi

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
config_path="${1:-$project_root/config.toml}"
launcher="$project_root/.venv/bin/fuzz-pipeline"
if [[ ! -x "$launcher" ]]; then
  echo "Run scripts/bootstrap_ubuntu.sh before installing the service." >&2
  exit 1
fi
if [[ ! -f "$config_path" ]]; then
  echo "Configuration file was not found: $config_path" >&2
  exit 1
fi
config_path="$(readlink -f "$config_path")"

config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
unit_dir="$config_home/systemd/user"
secret_dir="$config_home/ai-fuzz-bounty"
unit_path="$unit_dir/fuzz-central-agent.service"
environment_path="$secret_dir/agent.env"
mkdir -p "$unit_dir" "$secret_dir"

if [[ ! -f "$environment_path" ]]; then
  cat >"$environment_path" <<'EOF'
FUZZ_TELEGRAM_BOT_TOKEN=
FUZZ_TELEGRAM_CHAT_ID=
GITHUB_TOKEN=
EOF
fi
chmod 600 "$environment_path"

systemd_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

working_directory="$(systemd_quote "$project_root")"
environment_file="$(systemd_quote "$environment_path")"
exec_start="$(systemd_quote "$launcher") --config $(systemd_quote "$config_path") agent"
cat >"$unit_path" <<EOF
[Unit]
Description=AI Fuzz Central Agent
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$working_directory
EnvironmentFile=$environment_file
ExecStart=$exec_start
Restart=on-failure
RestartSec=30
TimeoutStopSec=180

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
echo "Installed $unit_path"
echo "Set credentials in $environment_path, then run:"
echo "  systemctl --user enable --now fuzz-central-agent.service"
