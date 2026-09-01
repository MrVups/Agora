#!/usr/bin/env bash
# ============================================================================
# Sub-Aggregator Panel Manager
# A menu-driven installer/manager that automates every manual step and
# gotcha discovered while deploying this project (Apache/Nginx conflicts,
# CGO builds, PasarGuard auto-config, security hardening, etc).
#
# Usage:
#   sudo bash panel-manager.sh
#
# Everything is in English on purpose: many terminals mangle Persian/RTL
# text, and this script is meant to be read carefully step by step.
# ============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Constants / paths
# ---------------------------------------------------------------------------
INSTALL_DIR="/opt/sub_aggregator"
BUILD_DIR="/opt/sub_aggregator_go"
BIN_PATH="${INSTALL_DIR}/sub_aggregator_go_bin"
SERVICE_NAME="sub_aggregator_go"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
OVERRIDE_DIR="/etc/systemd/system/${SERVICE_NAME}.service.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/override.conf"
SOCKET_PATH="/run/sub_aggregator/aggregator.sock"
STATE_FILE="${INSTALL_DIR}/panel-manager.state"
GH_REPO_DEFAULT="${SUB_AGG_GH_REPO:-MrVups/Agora}"

# Colors (fall back gracefully if the terminal doesn't support them)
if [ -t 1 ]; then
  C_RESET="\033[0m"; C_BOLD="\033[1m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_RED="\033[31m"; C_CYAN="\033[36m"
else
  C_RESET=""; C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""
fi

info()  { echo -e "${C_CYAN}[INFO]${C_RESET} $*" >&2; }
ok()    { echo -e "${C_GREEN}[OK]${C_RESET} $*" >&2; }
warn()  { echo -e "${C_YELLOW}[WARN]${C_RESET} $*" >&2; }
err()   { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }
step()  { echo -e "\n${C_BOLD}== $* ==${C_RESET}" >&2; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (use: sudo bash panel-manager.sh)"
    exit 1
  fi
}

# Always read interactive prompts from the real terminal, even if this
# script itself was invoked through a pipe (curl | bash). This avoids the
# repeated "nano saved an empty file" problem from manual sessions.
ask() {
  local prompt="$1" default="${2:-}" varname="$3"
  local answer=""
  if [ -n "$default" ]; then
    read -rp "$prompt [$default]: " answer < /dev/tty || true
    answer="${answer:-$default}"
  else
    read -rp "$prompt: " answer < /dev/tty || true
  fi
  printf -v "$varname" '%s' "$answer"
}

ask_secret() {
  local prompt="$1" varname="$3"
  local answer=""
  read -rsp "$prompt: " answer < /dev/tty || true
  echo "" > /dev/tty
  printf -v "$varname" '%s' "$answer"
}

confirm() {
  local prompt="$1" answer=""
  read -rp "$prompt [y/N]: " answer < /dev/tty || true
  [[ "$answer" =~ ^[Yy]$ ]]
}

save_state() {
  # Persist a key so future menu runs remember prior choices (domain, ports,
  # panel type, etc) instead of asking again every time.
  mkdir -p "$INSTALL_DIR"
  touch "$STATE_FILE"
  local key="$1" value="$2"
  grep -v "^${key}=" "$STATE_FILE" > "${STATE_FILE}.tmp" 2>/dev/null || true
  echo "${key}=${value}" >> "${STATE_FILE}.tmp"
  mv "${STATE_FILE}.tmp" "$STATE_FILE"
}

load_state() {
  local key="$1" default="${2:-}"
  if [ -f "$STATE_FILE" ]; then
    local v
    v=$(grep "^${key}=" "$STATE_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
    echo "${v:-$default}"
  else
    echo "$default"
  fi
}

# If this server was already configured manually (as most of the earlier
# testing in this project was), the state file starts out empty even though
# the real systemd/Apache config already has everything we need. Read the
# real config once and backfill the state file so the menu header and every
# other action work correctly without forcing a redundant "Full install".
sync_state_from_existing_install() {
  if [ -z "$(load_state panel_type)" ]; then
    # Ask systemd for the actual merged environment (main unit file +
    # override), instead of grepping either file individually — PANEL_TYPE
    # may live in either one depending on when it was set up.
    local merged_env
    merged_env=$(systemctl show "$SERVICE_NAME" -p Environment --value 2>/dev/null)
    if [ -n "$merged_env" ]; then
      local pt pg_port pg_path pg_scheme
      pt=$(echo "$merged_env" | grep -oE 'PANEL_TYPE=[a-zA-Z]+' | head -1 | cut -d= -f2)
      [ -n "$pt" ] && save_state "panel_type" "$pt"
      pg_port=$(echo "$merged_env" | grep -oE 'PASARGUARD_PORT=[0-9]+' | head -1 | cut -d= -f2)
      [ -n "$pg_port" ] && save_state "pg_port" "$pg_port"
      pg_path=$(echo "$merged_env" | grep -oE 'PASARGUARD_SUB_PATH=[^ "]+' | head -1 | cut -d= -f2)
      [ -n "$pg_path" ] && save_state "pg_path" "$(echo "$pg_path" | tr -d '/')"
      pg_scheme=$(echo "$merged_env" | grep -oE 'PASARGUARD_SCHEME=[a-z]+' | head -1 | cut -d= -f2)
      [ -n "$pg_scheme" ] && save_state "pg_scheme" "$pg_scheme"
    fi
  fi
  if [ -z "$(load_state domain)" ]; then
    local vhost_file found_domain
    vhost_file=$(grep -rl "unix:${SOCKET_PATH}" /etc/apache2/sites-enabled/*.conf 2>/dev/null | head -1)
    if [ -n "$vhost_file" ]; then
      found_domain=$(grep -oE "ServerName\s+\S+" "$vhost_file" | head -1 | awk '{print $2}')
      [ -n "$found_domain" ] && save_state "domain" "$found_domain"
    fi
  fi
}

pause() {
  read -rp "Press Enter to continue..." _ < /dev/tty || true
}

# ---------------------------------------------------------------------------
# Detection helpers (issues #1, #2, #4, #5, #7, #13, #14, #17 from the log)
# ---------------------------------------------------------------------------

detect_ram_mb() {
  awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "0"
}

check_ram_and_offer_swap() {
  local ram_mb
  ram_mb=$(detect_ram_mb)
  info "Detected RAM: ${ram_mb} MB"
  if [ "$ram_mb" -lt 900 ]; then
    warn "This server has less than 900MB RAM."
    warn "Compiling this project locally with CGO can take 1-4 HOURS on such"
    warn "a small server and may look 'stuck' (it isn't — it's swapping)."
    warn "STRONGLY RECOMMENDED: use the prebuilt-binary install method"
    warn "(menu option 1 -> 'Prebuilt binary from GitHub Releases') instead"
    warn "of building from source on this machine."
    if ! swapon --show | grep -q .; then
      if confirm "No swap detected. Add a 1GB swap file now (safer for any local build)?"; then
        fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
        ok "Swap file added and enabled."
      fi
    else
      ok "Swap already present."
    fi
  fi
}

check_go_toolchain() {
  if command -v go >/dev/null 2>&1; then
    ok "Go toolchain found: $(go version)"
    return 0
  fi
  return 1
}

install_go_toolchain() {
  step "Installing Go toolchain"
  local arch tarball
  arch=$(uname -m)
  case "$arch" in
    x86_64) tarball="go1.22.5.linux-amd64.tar.gz" ;;
    aarch64|arm64) tarball="go1.22.5.linux-arm64.tar.gz" ;;
    *) err "Unsupported architecture: $arch"; return 1 ;;
  esac
  curl -fsSL "https://go.dev/dl/${tarball}" -o /tmp/go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  if ! grep -q "/usr/local/go/bin" ~/.bashrc 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  fi
  export PATH=$PATH:/usr/local/go/bin
  ok "Go installed: $(go version)"
}

check_build_essential() {
  # Issue #4: CGO_ENABLED=0 silently breaks SQLite at RUNTIME, not build time.
  # A C compiler is mandatory for a local build.
  if command -v gcc >/dev/null 2>&1; then
    ok "gcc found: $(gcc --version | head -1)"
    return 0
  fi
  warn "No C compiler found. This project needs CGO (for SQLite) to work correctly."
  warn "Without it, the binary WILL start but silently fail on every database"
  warn "operation with: \"CGO_ENABLED=0, go-sqlite3 requires cgo... This is a stub\""
  if confirm "Install build-essential (gcc) now?"; then
    apt-get update -y && apt-get install -y build-essential
    ok "build-essential installed."
  else
    err "Cannot proceed with a local build without a C compiler."
    return 1
  fi
}

detect_web_server_conflicts() {
  # Issue #1: an orphaned Nginx install can steal port 443 from Apache
  # (or vice versa), causing confusing 502/503 errors that have nothing
  # to do with this project's own code.
  step "Checking for web server port conflicts"
  local apache_active nginx_active
  apache_active=$(systemctl is-active apache2 2>/dev/null || echo "inactive")
  nginx_active=$(systemctl is-active nginx 2>/dev/null || echo "inactive")

  info "Apache: $apache_active | Nginx: $nginx_active"

  if [ "$apache_active" = "active" ] && [ "$nginx_active" = "active" ]; then
    warn "BOTH Apache and Nginx are running. Only one can bind to port 443."
    warn "This exact situation caused hours of debugging in earlier deployments"
    warn "of this project (orphaned Nginx grabbing port 443 from Apache)."
    if confirm "Disable and stop Nginx now? (Apache will be used for this panel)"; then
      systemctl stop nginx
      systemctl disable nginx
      ok "Nginx stopped and disabled."
    else
      warn "Leaving both running. You are responsible for making sure they don't"
      warn "fight over the same port — this script will proceed assuming Apache."
    fi
  elif [ "$nginx_active" = "active" ] && [ "$apache_active" != "active" ]; then
    err "Only Nginx is active. This script currently automates Apache vhost"
    err "generation only. Please install/enable Apache, or ask for Nginx"
    err "support to be added, before continuing."
    return 1
  elif [ "$apache_active" != "active" ]; then
    warn "Apache is not active. Attempting to start/enable it."
    systemctl enable --now apache2 2>/dev/null || {
      err "Could not start Apache. Install it first: apt-get install -y apache2"
      return 1
    }
  fi

  a2enmod proxy proxy_http ssl >/dev/null 2>&1 || true
  return 0
}

detect_public_ip() {
  # Issue #7: testing against the wrong IP (or an IPv6-only default) caused
  # repeated false alarms. Always report BOTH and let the admin verify DNS.
  local ipv4 ipv6
  ipv4=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || echo "")
  ipv6=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null || echo "")
  info "Detected public IPv4: ${ipv4:-none}"
  info "Detected public IPv6: ${ipv6:-none}"
  if [ -z "$ipv4" ]; then
    warn "No IPv4 detected on this server. If any of your VPN inbounds serve"
    warn "real client traffic directly from this machine (not just the panel),"
    warn "IPv4-only clients will NOT be able to reach it. The panel/console"
    warn "itself is fine over IPv6 behind Cloudflare, but real VPN traffic is not."
  fi
  echo "$ipv4"
}

detect_panel_type() {
  # Issue #13/#14: PasarGuard is Docker-based with no fixed install path;
  # x-ui always lives at /etc/x-ui/x-ui.db. Prefer a definitive file check,
  # fall back to a Docker container name probe, then ask.
  step "Detecting panel type (x-ui vs PasarGuard)"
  if [ -f /etc/x-ui/x-ui.db ]; then
    ok "Found /etc/x-ui/x-ui.db -> panel type: xui"
    echo "xui"
    return
  fi
  if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qi pasarguard; then
      ok "Found a running PasarGuard Docker container -> panel type: pasarguard"
      echo "pasarguard"
      return
    fi
  fi
  warn "Could not auto-detect the panel type."
  local choice
  ask "Enter panel type manually (xui/pasarguard)" "xui" choice
  echo "$choice"
}

find_pasarguard_env() {
  # PasarGuard has no single guaranteed install path. Search common
  # locations, falling back to a full filesystem search as a last resort.
  local candidates=(/opt/pasarguard/.env /var/lib/pasarguard/.env)
  for c in "${candidates[@]}"; do
    if [ -f "$c" ]; then echo "$c"; return; fi
  done
  find / -maxdepth 5 -iname ".env" 2>/dev/null | xargs grep -l "SUBSCRIPTION\|UVICORN\|SQLALCHEMY" 2>/dev/null | head -1
}

parse_pasarguard_env() {
  # Reads UVICORN_PORT, subscription path, and whether PasarGuard terminates
  # its own TLS, straight from the real .env file instead of guessing.
  local env_file="$1"
  local port path scheme
  port=$(grep -E "^UVICORN_PORT" "$env_file" 2>/dev/null | head -1 | sed -E 's/.*=\s*"?([0-9]+)"?.*/\1/')
  path=$(grep -E "^(XRAY_SUBSCRIPTION_PATH|SUBSCRIPTION_PATH)" "$env_file" 2>/dev/null | grep -v "^#" | head -1 | sed -E 's/.*=\s*"?([^"]*)"?.*/\1/')
  if grep -qE "^UVICORN_SSL_CERTFILE" "$env_file" 2>/dev/null && ! grep -qE "^#\s*UVICORN_SSL_CERTFILE" "$env_file" 2>/dev/null; then
    scheme="https"
  else
    scheme="http"
  fi
  echo "${port:-8000}|${path:-sub}|${scheme}"
}

find_faoxima_config() {
  # Issue #17: MySQL credentials are buried inside the bot's own config.php.
  # Auto-discover instead of asking the admin to grep it manually.
  find /var/www -maxdepth 4 -iname "config.php" 2>/dev/null \
    | xargs grep -l "usernamedb\|passworddb" 2>/dev/null | head -1
}

parse_faoxima_config() {
  local cfg="$1"
  local user pass db
  user=$(grep -oE "\\\$usernamedb\s*=\s*'[^']*'" "$cfg" | sed -E "s/.*=\s*'([^']*)'/\1/")
  pass=$(grep -oE "\\\$passworddb\s*=\s*'[^']*'" "$cfg" | sed -E "s/.*=\s*'([^']*)'/\1/")
  db=$(grep -oE "\\\$dbname\s*=\s*'[^']*'" "$cfg" | sed -E "s/.*=\s*'([^']*)'/\1/")
  echo "${user}|${pass}|${db}"
}

# ---------------------------------------------------------------------------
# Binary install (two methods, mirroring issue #4/#5)
# ---------------------------------------------------------------------------

install_binary_prebuilt() {
  step "Installing prebuilt binary from GitHub Releases (recommended)"
  local gh_repo
  gh_repo=$(load_state "gh_repo" "$GH_REPO_DEFAULT")
  if [ -z "${SUB_AGG_GH_REPO:-}" ]; then
    ask "GitHub repo (user/repo) to pull releases from" "$gh_repo" gh_repo
  else
    gh_repo="${SUB_AGG_GH_REPO}"
  fi
  save_state "gh_repo" "$gh_repo"

  local arch asset
  arch=$(uname -m)
  case "$arch" in
    x86_64) asset="sub_aggregator_go_linux_amd64" ;;
    aarch64|arm64) asset="sub_aggregator_go_linux_arm64" ;;
    *) err "Unsupported architecture: $arch"; return 1 ;;
  esac

  local url
  url=$(curl -fsSL "https://api.github.com/repos/${gh_repo}/releases/latest" \
    | grep "browser_download_url" | grep "$asset" | cut -d '"' -f 4)

  if [ -z "$url" ]; then
    err "Could not find a release asset for ${asset} in ${gh_repo}."
    err "Make sure a release (tag vX.Y.Z) has been published and GitHub"
    err "Actions finished building it."
    return 1
  fi

  mkdir -p "$INSTALL_DIR"
  info "Downloading: $url"
  curl -fsSL "$url" -o "$BIN_PATH"
  chmod +x "$BIN_PATH"

  # Smoke-test before trusting this binary: a CGO/SQLite binary built on a
  # different glibc version can download fine and still fail to even start.
  # Catch that here instead of during a confusing later systemd failure.
  if ! "$BIN_PATH" version >/dev/null 2>&1; then
    err "The downloaded binary failed to run on this system."
    err "This usually means a glibc version mismatch between the GitHub"
    err "Actions build runner and this server. Try building from source"
    err "instead (menu option 1 -> method 2), or check that the release"
    err "workflow builds on a distro version compatible with this server."
    rm -f "$BIN_PATH"
    return 1
  fi
  ok "Binary installed and verified runnable at $BIN_PATH"
}

install_binary_from_source() {
  step "Building from source locally"
  check_ram_and_offer_swap
  if ! check_go_toolchain; then
    if confirm "Go toolchain not found. Install it now?"; then
      install_go_toolchain
    else
      err "Cannot build without Go."
      return 1
    fi
  fi
  if ! check_build_essential; then
    return 1
  fi

  mkdir -p "$BUILD_DIR"
  if [ ! -f "$BUILD_DIR/main.go" ]; then
    err "main.go not found in $BUILD_DIR."
    err "Copy main.go, go.mod, and go.sum into $BUILD_DIR first (e.g. via scp),"
    err "then re-run this option."
    return 1
  fi

  export PATH=$PATH:/usr/local/go/bin
  cd "$BUILD_DIR" || return 1
  info "Downloading Go module dependencies..."
  go mod download
  info "Building with CGO_ENABLED=1 (this is mandatory, see issue #4 in project notes)..."
  info "On a low-RAM server this can take a long time. Do not interrupt it."
  CGO_ENABLED=1 go build -o sub_aggregator_go_bin main.go || {
    err "Build failed. See the error above."
    return 1
  }

  local filetype
  filetype=$(file sub_aggregator_go_bin)
  if ! echo "$filetype" | grep -q "dynamically linked"; then
    err "Build succeeded but the binary is NOT dynamically linked."
    err "This usually means CGO was still disabled. SQLite will not work."
    return 1
  fi

  mkdir -p "$INSTALL_DIR"
  cp sub_aggregator_go_bin "$BIN_PATH"
  ok "Binary built and installed at $BIN_PATH"
}

# ---------------------------------------------------------------------------
# Systemd service generation (never via nano — issue #6)
# ---------------------------------------------------------------------------

write_systemd_unit() {
  step "Writing systemd service"
  mkdir -p "$INSTALL_DIR"
  cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Go Sub-Aggregator Service
After=network-online.target mysql.service x-ui.service docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  ok "Service file written to $SERVICE_FILE"
}

write_env_override() {
  # All environment variables live in one override file, generated
  # non-interactively via heredoc. This is the ONLY way config is ever
  # written — never through an interactive editor (issue #6).
  mkdir -p "$OVERRIDE_DIR"
  cat > "$OVERRIDE_FILE" << EOF
[Service]
$(for line in "$@"; do echo "$line"; done)
EOF
  systemctl daemon-reload
  ok "Environment written to $OVERRIDE_FILE"
}

restart_service() {
  systemctl restart "$SERVICE_NAME"
  sleep 1
  systemctl status "$SERVICE_NAME" --no-pager -l | head -12
}

# ---------------------------------------------------------------------------
# Apache vhost generation
# ---------------------------------------------------------------------------

setup_domain_and_cert() {
  step "Domain and SSL certificate"
  local domain
  domain=$(load_state "domain" "")
  ask "Domain for this aggregator panel (e.g. sub.example.com)" "$domain" domain
  save_state "domain" "$domain"

  local public_ip
  public_ip=$(detect_public_ip)
  warn "Make sure a DNS A record for '$domain' points to: ${public_ip:-<check manually>}"
  warn "If you use Cloudflare, keep the DNS record 'DNS only' (grey cloud) to"
  warn "avoid the SSL handshake issues seen earlier with Proxied mode."
  if ! confirm "Has the DNS record been created and had time to propagate?"; then
    warn "Set up DNS first, then re-run this step."
    return 1
  fi

  if [ -d "/etc/letsencrypt/live/${domain}" ]; then
    ok "A certificate for $domain already exists, skipping issuance."
  else
    if ! command -v certbot >/dev/null 2>&1; then
      info "Installing certbot..."
      apt-get update -y && apt-get install -y certbot python3-certbot-apache
    fi
    certbot certonly --apache -d "$domain" --non-interactive --agree-tos -m "admin@${domain}" --register-unsafely-without-email >&2 || \
      certbot certonly --apache -d "$domain" >&2 || {
        err "Certificate issuance failed."
        return 1
      }
    ok "Certificate issued for $domain."
  fi
  echo "$domain"
}

write_apache_vhost() {
  local domain="$1"
  step "Writing Apache vhost for $domain"

  # Remove any older/conflicting vhost file for the same domain first —
  # issue #2 (stale duplicate vhost pointing at a wrong backend) came from
  # never cleaning up before writing a new one.
  local old_confs
  old_confs=$(grep -rl "ServerName ${domain}" /etc/apache2/sites-enabled/ 2>/dev/null || true)
  if [ -n "$old_confs" ]; then
    warn "Found existing vhost file(s) referencing $domain — disabling them first:"
    for f in $old_confs; do
      local site_name
      site_name=$(basename "$f" .conf)
      echo "  - $site_name"
      a2dissite "$site_name" >/dev/null 2>&1 || true
    done
  fi

  cat > "/etc/apache2/sites-available/sub-aggregator-${domain}.conf" << EOF
<VirtualHost *:443>
    ServerName ${domain}

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${domain}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${domain}/privkey.pem

    ProxyPreserveHost On
    ProxyPass / unix:${SOCKET_PATH}|http://localhost/
    ProxyPassReverse / unix:${SOCKET_PATH}|http://localhost/
</VirtualHost>
EOF
  a2ensite "sub-aggregator-${domain}" >/dev/null 2>&1
  if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    systemctl reload apache2
    ok "Apache vhost enabled and reloaded."
  else
    err "Apache config test failed. Not reloading. Run 'apache2ctl configtest' to see why."
    return 1
  fi

  # Cosmetic fix for issue #20 (AH00558 ServerName warning noise).
  # Defense-in-depth: only ever write this if $domain is a single clean
  # hostname token — never trust it blindly, in case a future bug produces
  # a multi-line or malformed value here (this exact class of bug broke
  # Apache entirely during testing, so we guard against it explicitly now).
  if [[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    if ! grep -rq "^ServerName" /etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf 2>/dev/null; then
      echo "ServerName ${domain}" > /etc/apache2/conf-available/global-servername.conf
      a2enconf global-servername >/dev/null 2>&1
      if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
        systemctl reload apache2
      else
        err "Global ServerName fix produced an invalid config — reverting it."
        a2disconf global-servername >/dev/null 2>&1
        rm -f /etc/apache2/conf-available/global-servername.conf
        systemctl reload apache2
      fi
    fi
  else
    warn "Skipped the cosmetic global ServerName fix: '\$domain' did not look"
    warn "like a clean single hostname (got: '${domain:0:40}...'). This is a"
    warn "safety check, not an error — everything else still worked."
  fi
}

# ---------------------------------------------------------------------------
# PasarGuard-specific automation (issues #13, #14, #15, #16, #19)
# ---------------------------------------------------------------------------

pasarguard_get_token() {
  local pg_port="$1" pg_scheme="$2" user="$3" pass="$4"
  curl -s -X POST "${pg_scheme}://127.0.0.1:${pg_port}/api/admin/token" \
    -d "username=${user}&password=${pass}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

configure_pasarguard_url_prefix() {
  # Issue #19: this single empty setting silently causes every link issued
  # by the bot/panel to bypass the aggregator entirely. Automate it.
  step "Configuring PasarGuard subscription.url_prefix"
  local domain pg_port pg_scheme
  domain=$(load_state "domain" "")
  pg_port=$(load_state "pg_port" "8000")
  pg_scheme=$(load_state "pg_scheme" "http")

  if [ -z "$domain" ]; then
    warn "No domain saved yet. Run 'Install' first."
    return 1
  fi

  warn "PasarGuard's CLI has no 'admin create' command (confirmed via --help)."
  warn "You must already have an admin account created from the PasarGuard"
  warn "dashboard's setup flow, or via: docker exec <container> pasarguard-cli generate-temp-key"
  local pg_user pg_pass
  ask "PasarGuard admin username" "" pg_user
  ask_secret "PasarGuard admin password" "" pg_pass

  local token
  token=$(pasarguard_get_token "$pg_port" "$pg_scheme" "$pg_user" "$pg_pass")
  if [ -z "$token" ]; then
    err "Login failed. Check the username/password and that PasarGuard is running on port ${pg_port}."
    return 1
  fi
  ok "Logged in to PasarGuard API."

  local current_settings
  current_settings=$(curl -s "${pg_scheme}://127.0.0.1:${pg_port}/api/settings" -H "Authorization: Bearer $token")
  local new_settings
  new_settings=$(CURRENT_SETTINGS="$current_settings" NEW_URL_PREFIX="https://${domain}" python3 << 'PYEOF' 2>/dev/null
import json, os
data = json.loads(os.environ["CURRENT_SETTINGS"])
data.setdefault("subscription", {})["url_prefix"] = os.environ["NEW_URL_PREFIX"]
print(json.dumps(data))
PYEOF
)

  if [ -z "$new_settings" ]; then
    err "Could not parse/modify settings JSON automatically."
    warn "Please set it manually: PasarGuard Dashboard -> Settings -> Subscription -> URL Prefix = https://${domain}"
    return 1
  fi

  local put_result
  put_result=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${pg_scheme}://127.0.0.1:${pg_port}/api/settings" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    -d "$new_settings")

  if [ "$put_result" = "200" ] || [ "$put_result" = "204" ]; then
    ok "PasarGuard subscription.url_prefix set to https://${domain}"
    ok "Every link the bot/panel issues from now on will route through your aggregator."
  else
    err "API update returned HTTP $put_result — it may not support PUT on this endpoint."
    warn "Please set it manually instead: PasarGuard Dashboard -> Settings -> Subscription"
    warn "-> URL Prefix = https://${domain}"
  fi

  save_state "pg_admin_user" "$pg_user"
}

install_flow_pasarguard() {
  local env_file parsed pg_port pg_path pg_scheme
  env_file=$(find_pasarguard_env)
  if [ -n "$env_file" ]; then
    ok "Found PasarGuard config at: $env_file"
    parsed=$(parse_pasarguard_env "$env_file")
    pg_port=$(echo "$parsed" | cut -d'|' -f1)
    pg_path=$(echo "$parsed" | cut -d'|' -f2)
    pg_scheme=$(echo "$parsed" | cut -d'|' -f3)
    info "Detected: port=$pg_port path=$pg_path scheme=$pg_scheme"
  else
    warn "Could not auto-locate PasarGuard's .env file."
    ask "PasarGuard UVICORN_PORT" "8000" pg_port
    ask "PasarGuard subscription path (without slashes)" "sub" pg_path
    ask "PasarGuard internal scheme (http/https)" "http" pg_scheme
  fi
  save_state "pg_port" "$pg_port"
  save_state "pg_path" "$pg_path"
  save_state "pg_scheme" "$pg_scheme"

  local pg_admin_user="" pg_admin_pass=""
  if confirm "Set PasarGuard admin credentials now (needed for the group dropdown feature, optional)?"; then
    warn "Reminder: PasarGuard CLI cannot create an admin (no 'admin create' command)."
    warn "Use an account already created via the dashboard setup flow."
    ask "PasarGuard admin username" "" pg_admin_user
    ask_secret "PasarGuard admin password" "" pg_admin_pass
  fi

  local bot_format
  ask "Bot inbound-format for MySQL sync: 'plain' (Faoxima) or 'json_array' (legacy Mirza bot)" "plain" bot_format
  save_state "bot_format" "$bot_format"

  local mysql_user="" mysql_pass="" mysql_db=""
  local faoxima_cfg
  faoxima_cfg=$(find_faoxima_config)
  if [ -n "$faoxima_cfg" ]; then
    ok "Found a bot config.php at: $faoxima_cfg"
    if confirm "Auto-fill MySQL credentials from it?"; then
      local parsed_db
      parsed_db=$(parse_faoxima_config "$faoxima_cfg")
      mysql_user=$(echo "$parsed_db" | cut -d'|' -f1)
      mysql_pass=$(echo "$parsed_db" | cut -d'|' -f2)
      mysql_db=$(echo "$parsed_db" | cut -d'|' -f3)
      info "Detected MySQL user='${mysql_user}' db='${mysql_db}'"
    fi
  fi
  if [ -z "$mysql_user" ] && confirm "Configure MySQL bot-sync credentials manually?"; then
    ask "MySQL username" "" mysql_user
    ask_secret "MySQL password" "" mysql_pass
    ask "MySQL database name" "" mysql_db
  fi

  local env_lines=(
    "Environment=\"PANEL_TYPE=pasarguard\""
    "Environment=\"PASARGUARD_PORT=${pg_port}\""
    "Environment=\"PASARGUARD_SUB_PATH=/${pg_path}/\""
    "Environment=\"PASARGUARD_SCHEME=${pg_scheme}\""
    "Environment=\"BOT_INBOUND_FORMAT=${bot_format}\""
  )
  [ -n "$pg_admin_user" ] && env_lines+=("Environment=\"PASARGUARD_ADMIN_USER=${pg_admin_user}\"")
  [ -n "$pg_admin_pass" ] && env_lines+=("Environment=\"PASARGUARD_ADMIN_PASS=${pg_admin_pass}\"")
  [ -n "$mysql_user" ] && env_lines+=("Environment=\"MYSQL_USER=${mysql_user}\"")
  [ -n "$mysql_pass" ] && env_lines+=("Environment=\"MYSQL_PASS=${mysql_pass}\"")
  [ -n "$mysql_db" ] && env_lines+=("Environment=\"MYSQL_DB=${mysql_db}\"")

  write_env_override "${env_lines[@]}"
}

install_flow_xui() {
  warn "x-ui mode auto-detects its own subscription path/port/domain at RUNTIME"
  warn "by reading x-ui.db directly — no manual config needed for that part."
  local bot_format
  ask "Bot inbound-format for MySQL sync: 'plain' (Faoxima) or 'json_array' (legacy Mirza bot)" "json_array" bot_format
  save_state "bot_format" "$bot_format"

  local mysql_user="" mysql_pass="" mysql_db=""
  if confirm "Configure MySQL bot-sync credentials now?"; then
    ask "MySQL username" "" mysql_user
    ask_secret "MySQL password" "" mysql_pass
    ask "MySQL database name" "" mysql_db
  fi

  local env_lines=(
    "Environment=\"PANEL_TYPE=xui\""
    "Environment=\"BOT_INBOUND_FORMAT=${bot_format}\""
  )
  [ -n "$mysql_user" ] && env_lines+=("Environment=\"MYSQL_USER=${mysql_user}\"")
  [ -n "$mysql_pass" ] && env_lines+=("Environment=\"MYSQL_PASS=${mysql_pass}\"")
  [ -n "$mysql_db" ] && env_lines+=("Environment=\"MYSQL_DB=${mysql_db}\"")

  write_env_override "${env_lines[@]}"

  warn "Reminder: x-ui's own subscription Listen IP should be restricted to"
  warn "127.0.0.1 in the x-ui panel (Settings -> Subscribe Settings), so it is"
  warn "never reachable directly from the internet — only through this aggregator."
}

# ---------------------------------------------------------------------------
# Top-level menu actions
# ---------------------------------------------------------------------------

action_full_install() {
  step "Full install"
  check_ram_and_offer_swap
  detect_web_server_conflicts || { pause; return; }

  echo "Binary install method:"
  echo "  1) Prebuilt binary from GitHub Releases (fast, recommended, no compiler needed)"
  echo "  2) Build from source on this server (slow on low-RAM VPS, needs Go + gcc)"
  local method="${SUB_AGG_BINARY_METHOD:-}"
  if [ -z "$method" ]; then
    ask "Choose 1 or 2" "1" method
  fi
  if [ "$method" = "2" ]; then
    install_binary_from_source || { pause; return; }
  else
    install_binary_prebuilt || { pause; return; }
  fi

  local panel_type
  panel_type=$(detect_panel_type)
  save_state "panel_type" "$panel_type"

  if [ "$panel_type" = "pasarguard" ]; then
    install_flow_pasarguard
  else
    install_flow_xui
  fi

  write_systemd_unit
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  restart_service

  local domain
  domain=$(setup_domain_and_cert) || { pause; return; }
  write_apache_vhost "$domain" || { pause; return; }

  if [ "$panel_type" = "pasarguard" ]; then
    if confirm "Auto-configure PasarGuard's url_prefix to route through this domain now?"; then
      configure_pasarguard_url_prefix
    else
      warn "Remember to set it manually later (menu option 3), or links issued"
      warn "by the bot/panel will bypass this aggregator entirely."
    fi
  fi

  ok "Install complete."
  echo ""
  echo "Next steps:"
  echo "  - Open https://${domain}/aggr-console"
  echo "  - Log in with admin/admin and change the password immediately:"
  echo "      ${BIN_PATH} reset-admin-password admin <your-new-password>"
  echo "  - Add your mother subscription links from the console."
  pause
}

action_change_domain() {
  local domain
  domain=$(setup_domain_and_cert) || { pause; return; }
  write_apache_vhost "$domain"
  local panel_type
  panel_type=$(load_state "panel_type" "xui")
  if [ "$panel_type" = "pasarguard" ] && confirm "Update PasarGuard's url_prefix to the new domain too?"; then
    configure_pasarguard_url_prefix
  fi
  pause
}

action_change_pasarguard_settings() {
  local panel_type
  panel_type=$(load_state "panel_type" "")
  if [ "$panel_type" != "pasarguard" ]; then
    warn "Current panel type is not PasarGuard (it's '${panel_type:-unset}')."
    if ! confirm "Switch this installation to PasarGuard mode?"; then
      return
    fi
    save_state "panel_type" "pasarguard"
  fi
  install_flow_pasarguard
  restart_service
  pause
}

action_change_mysql() {
  local mysql_user mysql_pass mysql_db bot_format
  ask "MySQL username" "" mysql_user
  ask_secret "MySQL password" "" mysql_pass
  ask "MySQL database name" "" mysql_db
  ask "Bot inbound-format ('plain' for Faoxima, 'json_array' for legacy Mirza bot)" "plain" bot_format
  write_env_override \
    "Environment=\"MYSQL_USER=${mysql_user}\"" \
    "Environment=\"MYSQL_PASS=${mysql_pass}\"" \
    "Environment=\"MYSQL_DB=${mysql_db}\"" \
    "Environment=\"BOT_INBOUND_FORMAT=${bot_format}\""
  restart_service
  pause
}

action_update_binary() {
  install_binary_prebuilt || { pause; return; }
  restart_service
  pause
}

action_status() {
  step "Service status"
  systemctl status "$SERVICE_NAME" --no-pager -l | head -20
  echo ""
  step "Recent logs"
  journalctl -u "$SERVICE_NAME" -n 30 --no-pager
  pause
}

action_reset_admin_password() {
  local username newpass
  ask "Console username to reset" "admin" username
  ask_secret "New password" "" newpass
  if [ -z "$newpass" ]; then
    err "Password cannot be empty."
    pause
    return
  fi
  "$BIN_PATH" reset-admin-password "$username" "$newpass"
  local domain
  domain=$(load_state "domain" "")
  if [ -n "$domain" ]; then
    ok "Password reset. Log in at https://${domain}/aggr-console"
  else
    ok "Password reset. Log in at your panel's /aggr-console URL."
  fi
  pause
}

action_uninstall() {
  warn "This will stop the service, remove the systemd unit, and remove the"
  warn "binary. Your database (${INSTALL_DIR}/aggregator.db) will be kept"
  warn "unless you confirm deleting it separately."
  if ! confirm "Proceed with uninstall?"; then
    return
  fi
  systemctl stop "$SERVICE_NAME" 2>/dev/null
  systemctl disable "$SERVICE_NAME" 2>/dev/null
  rm -f "$SERVICE_FILE"
  rm -rf "$OVERRIDE_DIR"
  systemctl daemon-reload
  rm -f "$BIN_PATH"
  rm -f "$LAUNCHER_PATH"
  ok "Service, binary, and launcher (agora) removed."
  if confirm "Also delete the database (main links, cached configs, admin password)?"; then
    rm -rf "$INSTALL_DIR"
    ok "Database and project directory deleted."
  fi
  local domain
  domain=$(load_state "domain" "")
  if [ -n "$domain" ] && confirm "Also remove the Apache vhost for ${domain}?"; then
    a2dissite "sub-aggregator-${domain}" >/dev/null 2>&1
    rm -f "/etc/apache2/sites-available/sub-aggregator-${domain}.conf"
    systemctl reload apache2
    ok "Apache vhost removed."
  fi
  pause
  # Exit completely so the menu does not loop back after uninstall
  exit 0
}

# ---------------------------------------------------------------------------
# Security submenu (issue #21 + extras)
# ---------------------------------------------------------------------------

security_install_fail2ban() {
  step "Installing fail2ban (brute-force protection without IP-lockout risk)"
  warn "Unlike an IP allowlist, fail2ban only blocks an IP TEMPORARILY after"
  warn "repeated failed logins. If you (the admin) type the right password,"
  warn "you are never locked out — this is why it's preferred over a"
  warn "permanent IP allowlist for this kind of panel."
  apt-get update -y && apt-get install -y fail2ban

  cat > /etc/fail2ban/jail.d/sub-aggregator.conf << 'EOF'
[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/error.log
maxretry = 5
findtime = 600
bantime = 3600
EOF
  systemctl restart fail2ban
  ok "fail2ban installed and watching Apache authentication failures"
  ok "(this covers the /aggr-console Basic Auth, and PasarGuard's dashboard"
  ok "if it's also proxied through this same Apache instance)."
  pause
}

security_basic_auth() {
  step "Adding an extra HTTP Basic Auth layer"
  warn "This adds a SECOND password layer in front of a location on a"
  warn "specific Apache vhost — for example PasarGuard's own /dashboard/,"
  warn "which normally lives on PasarGuard's OWN domain, not this aggregator's"
  warn "domain. Getting the domain right here matters — the wrong domain"
  warn "means the password protects nothing real."

  local target_domain default_domain
  default_domain=$(load_state "pg_dashboard_domain" "")
  if [ -z "$default_domain" ]; then
    warn "PasarGuard's dashboard domain has not been recorded yet."
    warn "This is normally DIFFERENT from this aggregator's own domain"
    warn "(which is: $(load_state domain '(unknown)'))."
  fi
  ask "Which DOMAIN's vhost should be protected? (e.g. PasarGuard's dashboard domain)" "$default_domain" target_domain
  if [ -z "$target_domain" ]; then
    err "No domain given, aborting."
    pause
    return
  fi
  save_state "pg_dashboard_domain" "$target_domain"

  local conf_file
  conf_file=$(grep -rl "ServerName[[:space:]]\+${target_domain}\b" /etc/apache2/sites-available/*.conf 2>/dev/null | head -1)
  if [ -z "$conf_file" ]; then
    err "Could not find an Apache vhost file with ServerName ${target_domain}"
    err "in /etc/apache2/sites-available/. Nothing was changed."
    warn "List available vhosts and their domains with:"
    warn "  grep -H ServerName /etc/apache2/sites-available/*.conf"
    pause
    return
  fi
  ok "Found vhost file: $conf_file"

  local target_path htpasswd_user htpasswd_pass
  ask "Which path on ${target_domain} should be protected? (e.g. /dashboard/)" "/dashboard/" target_path
  ask "New Basic Auth username" "admin" htpasswd_user
  ask_secret "New Basic Auth password" "" htpasswd_pass

  mkdir -p /etc/apache2/secrets
  htpasswd -bc /etc/apache2/secrets/sub-aggregator.htpasswd "$htpasswd_user" "$htpasswd_pass" >/dev/null 2>&1 || {
    apt-get install -y apache2-utils
    htpasswd -bc /etc/apache2/secrets/sub-aggregator.htpasswd "$htpasswd_user" "$htpasswd_pass"
  }

  if grep -q "AuthType Basic" "$conf_file"; then
    warn "This vhost already has a Basic Auth block. Not adding a second one."
    warn "Edit $conf_file manually if you need to change it."
    pause
    return
  fi

  cp "$conf_file" "${conf_file}.bak-$(date +%s)"
  python3 - "$conf_file" "$target_path" << 'PYEOF'
import sys
conf_file, target_path = sys.argv[1], sys.argv[2]
with open(conf_file) as f:
    content = f.read()
block = f'''
    <Location "{target_path}">
        AuthType Basic
        AuthName "Restricted"
        AuthUserFile /etc/apache2/secrets/sub-aggregator.htpasswd
        Require valid-user
    </Location>
'''
content = content.replace("</VirtualHost>", block + "</VirtualHost>")
with open(conf_file, "w") as f:
    f.write(content)
PYEOF

  if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    systemctl reload apache2
    ok "Basic Auth added for ${target_path} on ${target_domain} (backup saved as ${conf_file}.bak-*)"
    ok "Test it now: curl -k -o /dev/null -w '%{http_code}\\n' https://${target_domain}${target_path}"
    ok "(should return 401 until you provide the new username/password)"
  else
    err "The edited config failed apache2ctl configtest — reverting from backup."
    cp "${conf_file}.bak-"* "$conf_file" 2>/dev/null
    systemctl reload apache2
  fi
  pause
}

security_enable_pg_login_notifications() {
  step "Enabling PasarGuard login notifications"
  warn "This lets you get notified on every admin login (even successful ones)"
  warn "so you notice unfamiliar IPs WITHOUT ever risking locking yourself out"
  warn "(unlike an IP allowlist)."
  local pg_port pg_scheme pg_user pg_pass
  pg_port=$(load_state "pg_port" "8000")
  pg_scheme=$(load_state "pg_scheme" "http")
  ask "PasarGuard admin username" "$(load_state pg_admin_user)" pg_user
  ask_secret "PasarGuard admin password" "" pg_pass

  local token
  token=$(pasarguard_get_token "$pg_port" "$pg_scheme" "$pg_user" "$pg_pass")
  if [ -z "$token" ]; then
    err "Login failed."
    pause
    return
  fi

  local current_settings new_settings
  current_settings=$(curl -s "${pg_scheme}://127.0.0.1:${pg_port}/api/settings" -H "Authorization: Bearer $token")
  new_settings=$(CURRENT_SETTINGS="$current_settings" python3 << 'PYEOF' 2>/dev/null
import json, os
data = json.loads(os.environ["CURRENT_SETTINGS"])
ne = data.setdefault("notification_enable", {})
ne.setdefault("admin", {})["login"] = True
print(json.dumps(data))
PYEOF
)

  if [ -z "$new_settings" ]; then
    err "Could not parse settings automatically."
    warn "Enable manually: PasarGuard Dashboard -> Settings -> Notifications ->"
    warn "Admin -> Login = on. Also make sure notify_telegram is configured."
    pause
    return
  fi

  local put_result
  put_result=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${pg_scheme}://127.0.0.1:${pg_port}/api/settings" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$new_settings")

  if [ "$put_result" = "200" ] || [ "$put_result" = "204" ]; then
    ok "Login notifications enabled."
    warn "Make sure Telegram notifications are also configured (token + chat id)"
    warn "in PasarGuard's settings, or this toggle alone won't send anything."
  else
    err "API update returned HTTP $put_result."
    warn "Enable manually: PasarGuard Dashboard -> Settings -> Notifications ->"
    warn "Admin -> Login = on."
  fi
  pause
}

security_rotate_pg_password_reminder() {
  step "Rotate PasarGuard admin password"
  warn "This script cannot change your PasarGuard admin password directly"
  warn "(there is no safe API for an admin to change their own password"
  warn "without a confirmed contract, and getting this wrong could lock you"
  warn "out of PasarGuard itself, which is worse than not automating it)."
  echo ""
  echo "Please change it manually: PasarGuard Dashboard -> Admins -> Edit -> Password"
  echo "Do this now if the current password has ever been shown in a terminal,"
  echo "log file, or chat history."
  pause
}

security_menu() {
  while true; do
    step "Security"
    echo " 1) Install fail2ban (brute-force protection, no lockout risk)"
    echo " 2) Add extra HTTP Basic Auth in front of a path (e.g. PasarGuard dashboard)"
    echo " 3) Enable PasarGuard login notifications"
    echo " 4) Reminder: rotate PasarGuard admin password (manual, on purpose)"
    echo " 0) Back"
    local choice
    ask "Choose an option" "0" choice
    case "$choice" in
      1) security_install_fail2ban ;;
      2) security_basic_auth ;;
      3) security_enable_pg_login_notifications ;;
      4) security_rotate_pg_password_reminder ;;
      0) return ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

main_menu() {
  while true; do
    echo ""
    echo "=================================================================="
    echo "  Sub-Aggregator Panel Manager"
    echo "  Panel type: $(load_state panel_type '(not installed yet)')  |  Domain: $(load_state domain '(none)')"
    echo "=================================================================="
    echo " 1) Full install (first time)"
    echo " 2) Change domain"
    echo " 3) Change PasarGuard settings (port/path/admin/MySQL)"
    echo " 4) Change MySQL / bot-sync credentials"
    echo " 5) Update binary from GitHub"
    echo " 6) Service status and logs"
    echo " 7) Reset console admin password"
    echo " 8) Security"
    echo " 9) Uninstall"
    echo " 0) Exit"
    echo "=================================================================="
    local choice
    ask "Choose an option" "0" choice
    case "$choice" in
      1) action_full_install ;;
      2) action_change_domain ;;
      3) action_change_pasarguard_settings ;;
      4) action_change_mysql ;;
      5) action_update_binary ;;
      6) action_status ;;
      7) action_reset_admin_password ;;
      8) security_menu ;;
      9) action_uninstall ;;
      0) echo "Bye."; exit 0 ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Global "agora" launcher command
# ---------------------------------------------------------------------------

LAUNCHER_PATH="/usr/local/bin/agora"
SCRIPT_REAL_PATH="$(readlink -f "${BASH_SOURCE[0]}")"

install_launcher_command() {
  if [ -f "$LAUNCHER_PATH" ] && [ "$(readlink -f "$LAUNCHER_PATH" 2>/dev/null)" = "$SCRIPT_REAL_PATH" ]; then
    return
  fi
  cat > "$LAUNCHER_PATH" << EOF
#!/usr/bin/env bash
exec sudo bash "${SCRIPT_REAL_PATH}" "\$@"
EOF
  chmod +x "$LAUNCHER_PATH"
  ok "Installed a global launcher: you can now just type 'agora' from anywhere to open this menu."
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

require_root
mkdir -p "$INSTALL_DIR"
install_launcher_command
sync_state_from_existing_install

if [ "${SUB_AGG_INSTALL_MODE:-}" = "full" ]; then
  action_full_install
  exit $?
fi

main_menu
