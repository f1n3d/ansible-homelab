#!/usr/bin/env bash
# =============================================================================
# Ansible Homelab - Interactive Setup Script
# =============================================================================
# Configures this repository for your infrastructure by asking for all
# necessary values and populating the configuration files.
#
# Usage:
#   ./setup.sh              # Fresh setup
#   ./setup.sh --reconfigure # Re-run with previous answers as defaults
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors & Formatting
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSWERS_FILE="${SCRIPT_DIR}/.setup-answers.env"
RECONFIGURE=false

# Service arrays
AVAILABLE_SERVICES=("paperless" "docmost" "samba" "cloudflared" "authentik" "website" "logging")
SERVICE_NAMES=("Paperless-NGX" "Docmost" "Samba" "Cloudflared" "Authentik" "Website" "Logging")
SERVICE_DESCRIPTIONS=(
    "Document management with OCR"
    "Documentation / Wiki platform"
    "Network file sharing (SMB)"
    "Cloudflare Tunnel for external access"
    "Identity Provider (OIDC/SSO)"
    "nginx web server with contact form"
    "Centralized logging (Loki + Grafana + Alloy)"
)
SELECTED_SERVICES=()

# Service → inventory group mapping
declare -A SERVICE_HOST_MAP=(
    [paperless]="paperless-server"
    [docmost]="docmost-server"
    [samba]="samba-server"
    [cloudflared]="cloudflared-server"
    [authentik]="authentik-server"
    [website]="website-server"
    [logging]="chronicle-server"
)

declare -A SERVICE_GROUP_MAP=(
    [paperless]="paperless"
    [docmost]="docmost"
    [samba]="samba"
    [cloudflared]="cloudflared"
    [authentik]="authentik"
    [website]="website"
    [logging]="chronicle"
)

# Collected configuration values
declare -A CONFIG=()

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${CYAN}── $1 ──${NC}"
    echo ""
}

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Prompt with default value. Usage: prompt_with_default "Label" "default_value" "config_key"
prompt_with_default() {
    local label="$1"
    local default="$2"
    local key="$3"
    local value

    if [[ -n "$default" ]]; then
        read -rp "  ${label} [${default}]: " value
        value="${value:-$default}"
    else
        read -rp "  ${label}: " value
        while [[ -z "$value" ]]; do
            error "This field is required."
            read -rp "  ${label}: " value
        done
    fi

    CONFIG[$key]="$value"
}

# Prompt for password with auto-generation option
prompt_password() {
    local label="$1"
    local key="$2"
    local auto_generated
    auto_generated="$(openssl rand -base64 32 2>/dev/null | tr -d '/+=' | head -c 32)"

    echo -e "  ${label}"
    echo -e "    ${YELLOW}Auto-generated: ${auto_generated}${NC}"
    read -rp "    Press Enter to accept, or type your own: " value
    value="${value:-$auto_generated}"

    CONFIG[$key]="$value"
}

# Prompt for secret key (longer)
prompt_secret_key() {
    local label="$1"
    local key="$2"
    local auto_generated
    auto_generated="$(openssl rand -base64 50 2>/dev/null | tr -d '/+=' | head -c 50)"

    echo -e "  ${label}"
    echo -e "    ${YELLOW}Auto-generated: ${auto_generated}${NC}"
    read -rp "    Press Enter to accept, or type your own: " value
    value="${value:-$auto_generated}"

    CONFIG[$key]="$value"
}

# Validate IP address format
validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# Prompt for IP with validation
prompt_ip() {
    local label="$1"
    local default="$2"
    local key="$3"
    local value

    read -rp "  ${label} [${default}]: " value
    value="${value:-$default}"

    while ! validate_ip "$value"; do
        error "Invalid IP address format. Please use format: x.x.x.x"
        read -rp "  ${label} [${default}]: " value
        value="${value:-$default}"
    done

    CONFIG[$key]="$value"
}

# Check if a service is selected
is_selected() {
    local service="$1"
    for s in "${SELECTED_SERVICES[@]}"; do
        [[ "$s" == "$service" ]] && return 0
    done
    return 1
}

# Save answers to file for --reconfigure
save_answers() {
    {
        echo "# Ansible Homelab Setup Answers (auto-generated)"
        echo "# Re-run with: ./setup.sh --reconfigure"
        echo "SELECTED_SERVICES=\"${SELECTED_SERVICES[*]}\""
        for key in "${!CONFIG[@]}"; do
            # Don't save passwords to the answers file
            if [[ "$key" != *"password"* && "$key" != *"secret"* && "$key" != *"token"* ]]; then
                echo "CONFIG_${key}=\"${CONFIG[$key]}\""
            fi
        done
    } > "$ANSWERS_FILE"
    chmod 600 "$ANSWERS_FILE"
}

# Load previous answers
load_answers() {
    if [[ -f "$ANSWERS_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$ANSWERS_FILE"
        if [[ -n "${SELECTED_SERVICES:-}" ]]; then
            read -ra SELECTED_SERVICES <<< "$SELECTED_SERVICES"
        fi
        # Load CONFIG values
        while IFS='=' read -r key value; do
            if [[ "$key" == CONFIG_* ]]; then
                local config_key="${key#CONFIG_}"
                CONFIG[$config_key]="${value//\"/}"
            fi
        done < "$ANSWERS_FILE"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Section 1: Welcome & Prerequisites
# ---------------------------------------------------------------------------
section_welcome() {
    clear
    echo ""
    echo -e "${BOLD}${BLUE}"
    echo "    ╔═══════════════════════════════════════════════════════════╗"
    echo "    ║          Ansible Homelab - Interactive Setup             ║"
    echo "    ║                                                         ║"
    echo "    ║   Automated LXC container management with Docker,       ║"
    echo "    ║   hardened security baseline, and modular services.      ║"
    echo "    ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    print_section "Checking Prerequisites"

    local missing=0

    if command -v ansible >/dev/null 2>&1; then
        info "ansible found: $(ansible --version | head -1)"
    else
        error "ansible not found. Install with: pip3 install ansible"
        missing=1
    fi

    if command -v ansible-vault >/dev/null 2>&1; then
        info "ansible-vault found"
    else
        error "ansible-vault not found. Install with: pip3 install ansible"
        missing=1
    fi

    if command -v openssl >/dev/null 2>&1; then
        info "openssl found (for password generation)"
    else
        error "openssl not found. Please install openssl."
        missing=1
    fi

    if command -v python3 >/dev/null 2>&1; then
        info "python3 found: $(python3 --version)"
    else
        error "python3 not found."
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        echo ""
        error "Missing prerequisites. Please install them and re-run this script."
        exit 1
    fi

    echo ""
    info "All prerequisites met!"
}

# ---------------------------------------------------------------------------
# Section 2: Service Selection
# ---------------------------------------------------------------------------
section_service_selection() {
    print_header "Service Selection"

    echo "  Which services would you like to deploy?"
    echo "  (Baseline security hardening is always included)"
    echo ""

    for i in "${!AVAILABLE_SERVICES[@]}"; do
        local num=$((i + 1))
        local preselected=""
        if $RECONFIGURE && is_selected "${AVAILABLE_SERVICES[$i]}" 2>/dev/null; then
            preselected=" ${GREEN}(previously selected)${NC}"
        fi
        echo -e "    [${BOLD}${num}${NC}] ${SERVICE_NAMES[$i]} - ${SERVICE_DESCRIPTIONS[$i]}${preselected}"
    done

    echo ""
    echo "  Enter numbers separated by spaces (e.g., \"1 3 5 7\")"
    echo "  Enter \"all\" to select everything"
    echo ""

    local selection
    read -rp "  Your selection: " selection

    if [[ "$selection" == "all" ]]; then
        SELECTED_SERVICES=("${AVAILABLE_SERVICES[@]}")
    else
        SELECTED_SERVICES=()
        for num in $selection; do
            local idx=$((num - 1))
            if [[ $idx -ge 0 && $idx -lt ${#AVAILABLE_SERVICES[@]} ]]; then
                SELECTED_SERVICES+=("${AVAILABLE_SERVICES[$idx]}")
            else
                warn "Ignoring invalid selection: $num"
            fi
        done
    fi

    if [[ ${#SELECTED_SERVICES[@]} -eq 0 ]]; then
        error "No services selected. At least one service is required."
        exit 1
    fi

    echo ""
    info "Selected services:"
    for s in "${SELECTED_SERVICES[@]}"; do
        echo -e "    ${GREEN}✓${NC} $s"
    done

    # Warnings
    if ! is_selected "cloudflared"; then
        echo ""
        warn "Cloudflared not selected. You will need to set up external access manually."
    fi

    if ! is_selected "authentik"; then
        if is_selected "paperless" || is_selected "logging"; then
            echo ""
            warn "Authentik not selected. OIDC/SSO will be disabled for Paperless and Grafana."
        fi
    fi
}

# ---------------------------------------------------------------------------
# Section 3: Network Configuration
# ---------------------------------------------------------------------------
section_network() {
    print_header "Network Configuration"

    echo "  Configure IP addresses for your LXC containers."
    echo "  These must be reachable from your Ansible control machine."
    echo ""

    prompt_with_default "Network subnet (for documentation)" "192.168.1.0/24" "subnet"

    # Extract base from subnet for defaults
    local base
    base=$(echo "${CONFIG[subnet]}" | sed 's/\.[0-9]*\/.*/./')
    local ip_counter=10

    for service in "${SELECTED_SERVICES[@]}"; do
        local host="${SERVICE_HOST_MAP[$service]}"
        local default_ip="${base}${ip_counter}"
        prompt_ip "$host IP address" "$default_ip" "ip_${service}"
        ip_counter=$((ip_counter + 1))
    done
}

# ---------------------------------------------------------------------------
# Section 4: Domain Configuration
# ---------------------------------------------------------------------------
section_domains() {
    print_header "Domain Configuration"

    echo "  Configure domains for services that need external access."
    echo "  Leave defaults if you plan to configure later."
    echo ""

    if is_selected "authentik"; then
        prompt_with_default "Authentik domain" "auth.example.com" "authentik_domain"
    fi

    if is_selected "website"; then
        prompt_with_default "Website domain" "www.example.com" "website_domain"
    fi

    if is_selected "paperless"; then
        prompt_with_default "Paperless URL (full URL with https://)" "https://paperless.example.com" "paperless_url"
    fi

    if is_selected "docmost"; then
        prompt_with_default "Docmost URL (full URL with https://)" "https://docs.example.com" "docmost_url"
    fi

    if is_selected "logging"; then
        prompt_with_default "Grafana domain" "grafana.example.com" "grafana_domain"
    fi
}

# ---------------------------------------------------------------------------
# Section 5: Service-Specific Configuration
# ---------------------------------------------------------------------------
section_paperless() {
    print_section "Paperless-NGX Configuration"

    prompt_with_default "Timezone" "UTC" "paperless_timezone"
    prompt_with_default "OCR language (e.g., eng, deu+eng, fra)" "eng" "paperless_ocr_language"
    prompt_with_default "Admin username" "admin" "paperless_admin_user"
    prompt_with_default "Admin email" "admin@example.com" "paperless_admin_email"
    prompt_password "Admin password:" "paperless_admin_password"
    prompt_password "PostgreSQL password:" "paperless_postgres_password"
    prompt_secret_key "Secret key (session encryption):" "paperless_secret_key"

    if is_selected "authentik"; then
        echo ""
        read -rp "  Enable OIDC/SSO via Authentik? [y/N]: " enable_oidc
        if [[ "$enable_oidc" =~ ^[Yy] ]]; then
            CONFIG[paperless_oidc_enabled]="true"
            prompt_with_default "OIDC Client ID (from Authentik)" "" "paperless_oidc_client_id"
            prompt_with_default "OIDC Client Secret (from Authentik)" "" "paperless_oidc_client_secret"
        else
            CONFIG[paperless_oidc_enabled]="false"
        fi
    fi
}

section_docmost() {
    print_section "Docmost Configuration"

    prompt_password "PostgreSQL password:" "docmost_postgres_password"
    prompt_secret_key "Application secret:" "docmost_app_secret"

    echo ""
    echo "  SMTP Configuration (for email notifications):"
    prompt_with_default "SMTP host" "smtp.example.com" "docmost_smtp_host"
    prompt_with_default "SMTP username" "user@example.com" "docmost_smtp_username"
    prompt_password "SMTP password:" "docmost_smtp_password"
    prompt_with_default "Mail from address" "docs@example.com" "docmost_mail_from_address"
    prompt_with_default "Mail from name" "Docmost" "docmost_mail_from_name"
}

section_samba() {
    print_section "Samba Configuration"

    prompt_with_default "SMB username" "smbuser" "samba_user"
    prompt_password "SMB password:" "samba_password"
    prompt_with_default "Share name" "storage" "samba_share_name"
    prompt_with_default "Host path (mount point on LXC)" "/mnt/storage" "samba_host_path"
    prompt_with_default "UID for file access" "1100" "samba_uid"
    prompt_with_default "GID for file access" "1100" "samba_gid"
}

section_cloudflared() {
    print_section "Cloudflared Configuration"

    echo "  Get your tunnel token from the Cloudflare Zero Trust dashboard:"
    echo "  https://one.dash.cloudflare.com -> Networks -> Tunnels"
    echo ""
    prompt_with_default "Tunnel token" "" "cloudflared_tunnel_token"
}

section_authentik() {
    print_section "Authentik Configuration"

    prompt_password "PostgreSQL password:" "authentik_postgres_password"
    prompt_secret_key "Secret key (session encryption):" "authentik_secret_key"

    echo ""
    read -rp "  Configure SMTP for Authentik email notifications? [y/N]: " enable_smtp
    if [[ "$enable_smtp" =~ ^[Yy] ]]; then
        prompt_with_default "SMTP host" "smtp.example.com" "authentik_smtp_host"
        prompt_with_default "SMTP username" "user@example.com" "authentik_smtp_username"
        prompt_password "SMTP password:" "authentik_smtp_password"
        prompt_with_default "Email from address" "authentik@example.com" "authentik_email_from"
    fi
}

section_website() {
    print_section "Website Configuration"

    echo "  Contact form email configuration:"
    prompt_with_default "Contact form recipient email" "contact@example.com" "contact_recipient"
    prompt_with_default "Sender email address" "sender@example.com" "contact_sender"

    echo ""
    echo "  SMTP Relay Configuration (for sending contact form emails):"
    prompt_with_default "SMTP relay host (e.g., [smtp.gmail.com]:587)" "[smtp.example.com]:587" "postfix_relay_host"
    prompt_with_default "SMTP username" "sender@example.com" "postfix_sasl_user"
    prompt_password "SMTP password:" "postfix_sasl_password"
}

section_logging() {
    print_section "Logging Stack Configuration (Loki + Grafana)"

    prompt_with_default "Grafana admin username" "admin" "grafana_admin_user"
    prompt_password "Grafana admin password:" "grafana_admin_password"

    if is_selected "authentik"; then
        echo ""
        read -rp "  Enable OIDC/SSO for Grafana via Authentik? [y/N]: " enable_oidc
        if [[ "$enable_oidc" =~ ^[Yy] ]]; then
            CONFIG[grafana_oidc_enabled]="true"
            prompt_with_default "OIDC Client ID (from Authentik)" "" "grafana_oidc_client_id"
            prompt_with_default "OIDC Client Secret (from Authentik)" "" "grafana_oidc_client_secret"
            prompt_with_default "OIDC Issuer URL" "https://${CONFIG[authentik_domain]:-auth.example.com}/application/o/grafana/" "grafana_oidc_issuer"
        else
            CONFIG[grafana_oidc_enabled]="false"
        fi
    else
        CONFIG[grafana_oidc_enabled]="false"
    fi
}

section_service_config() {
    print_header "Service Configuration"

    for service in "${SELECTED_SERVICES[@]}"; do
        case "$service" in
            paperless)  section_paperless ;;
            docmost)    section_docmost ;;
            samba)      section_samba ;;
            cloudflared) section_cloudflared ;;
            authentik)  section_authentik ;;
            website)    section_website ;;
            logging)    section_logging ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Section 6: Summary
# ---------------------------------------------------------------------------
section_summary() {
    print_header "Configuration Summary"

    echo -e "  ${BOLD}Selected Services:${NC}"
    for s in "${SELECTED_SERVICES[@]}"; do
        local host="${SERVICE_HOST_MAP[$s]}"
        local ip="${CONFIG[ip_${s}]:-not set}"
        echo -e "    ${GREEN}✓${NC} ${s} (${host} @ ${ip})"
    done

    echo ""
    echo -e "  ${BOLD}Domains:${NC}"
    [[ -n "${CONFIG[authentik_domain]:-}" ]] && echo "    Authentik:  ${CONFIG[authentik_domain]}"
    [[ -n "${CONFIG[website_domain]:-}" ]]   && echo "    Website:    ${CONFIG[website_domain]}"
    [[ -n "${CONFIG[paperless_url]:-}" ]]    && echo "    Paperless:  ${CONFIG[paperless_url]}"
    [[ -n "${CONFIG[docmost_url]:-}" ]]      && echo "    Docmost:    ${CONFIG[docmost_url]}"
    [[ -n "${CONFIG[grafana_domain]:-}" ]]   && echo "    Grafana:    ${CONFIG[grafana_domain]}"

    echo ""
    echo -e "  ${BOLD}Credentials:${NC} (passwords hidden)"
    for key in "${!CONFIG[@]}"; do
        if [[ "$key" == *"password"* || "$key" == *"secret"* || "$key" == *"token"* ]]; then
            echo "    ${key}: ****"
        fi
    done

    echo ""
    read -rp "  Proceed with this configuration? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
        echo ""
        error "Setup cancelled. Run again to reconfigure."
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# Section 7: Apply Configuration
# ---------------------------------------------------------------------------
apply_inventory() {
    print_section "Generating inventory/hosts.yml"

    cat > "${SCRIPT_DIR}/inventory/hosts.yml" << INVENTORY_EOF
---
# Ansible Inventory for LXC Containers
# Generated by setup.sh

all:
  children:
    # Group for all LXC containers (used by baseline.yml)
    lxc_containers:
      hosts:
        localhost:
          ansible_connection: local
INVENTORY_EOF

    # Add selected hosts
    for service in "${SELECTED_SERVICES[@]}"; do
        local host="${SERVICE_HOST_MAP[$service]}"
        local ip="${CONFIG[ip_${service}]}"
        cat >> "${SCRIPT_DIR}/inventory/hosts.yml" << EOF
        ${host}:
          ansible_host: ${ip}
EOF
    done

    cat >> "${SCRIPT_DIR}/inventory/hosts.yml" << 'EOF'

      vars:
        ansible_user: root
        ansible_python_interpreter: /usr/bin/python3

    # Application-specific groups
EOF

    # Add group definitions
    for service in "${SELECTED_SERVICES[@]}"; do
        local group="${SERVICE_GROUP_MAP[$service]}"
        local host="${SERVICE_HOST_MAP[$service]}"
        cat >> "${SCRIPT_DIR}/inventory/hosts.yml" << EOF
    ${group}:
      hosts:
        ${host}:

EOF
    done

    info "inventory/hosts.yml generated"
}

apply_global_vars() {
    print_section "Updating global variables"

    if is_selected "logging"; then
        local loki_ip="${CONFIG[ip_logging]}"
        cat > "${SCRIPT_DIR}/inventory/group_vars/all.yml" << EOF
---
# =============================================================================
# Global Variables (all hosts)
# =============================================================================

# =============================================================================
# Loki Endpoints (Logging Stack)
# =============================================================================
# Central logging server configuration
loki_host: ${loki_ip}
loki_port: 3100
loki_url: "http://{{ loki_host }}:{{ loki_port }}"
loki_push_endpoint: "{{ loki_url }}/loki/api/v1/push"
EOF
        info "inventory/group_vars/all.yml updated with Loki IP: ${loki_ip}"
    else
        cat > "${SCRIPT_DIR}/inventory/group_vars/all.yml" << 'EOF'
---
# =============================================================================
# Global Variables (all hosts)
# =============================================================================
# Add global variables here
EOF
        info "inventory/group_vars/all.yml updated (logging not selected)"
    fi
}

apply_defaults() {
    print_section "Updating role defaults"

    # Paperless
    if is_selected "paperless"; then
        local file="${SCRIPT_DIR}/roles/paperless/defaults/main.yml"
        sed -i.bak "s|^paperless_timezone:.*|paperless_timezone: \"${CONFIG[paperless_timezone]:-UTC}\"|" "$file"
        sed -i.bak "s|^paperless_ocr_language:.*|paperless_ocr_language: \"${CONFIG[paperless_ocr_language]:-eng}\"|" "$file"
        if [[ "${CONFIG[paperless_oidc_enabled]:-false}" == "true" ]]; then
            sed -i.bak "s|^paperless_oidc_enabled:.*|paperless_oidc_enabled: true|" "$file"
        fi
        rm -f "${file}.bak"
        info "roles/paperless/defaults/main.yml updated"
    fi

    # Authentik
    if is_selected "authentik"; then
        local file="${SCRIPT_DIR}/roles/authentik/defaults/main.yml"
        sed -i.bak "s|^authentik_domain:.*|authentik_domain: ${CONFIG[authentik_domain]:-auth.example.com}|" "$file"
        rm -f "${file}.bak"
        info "roles/authentik/defaults/main.yml updated"
    fi

    # Website
    if is_selected "website"; then
        local file="${SCRIPT_DIR}/roles/website/defaults/main.yml"
        sed -i.bak "s|^website_domain:.*|website_domain: ${CONFIG[website_domain]:-www.example.com}|" "$file"
        sed -i.bak "s|^contact_api_recipient:.*|contact_api_recipient: \"${CONFIG[contact_recipient]:-contact@example.com}\"|" "$file"
        sed -i.bak "s|^contact_api_sender:.*|contact_api_sender: \"${CONFIG[contact_sender]:-sender@example.com}\"|" "$file"
        sed -i.bak "s|^postfix_relay_host:.*|postfix_relay_host: \"${CONFIG[postfix_relay_host]:-[smtp.example.com]:587}\"|" "$file"
        sed -i.bak "s|^postfix_sasl_user:.*|postfix_sasl_user: \"${CONFIG[postfix_sasl_user]:-sender@example.com}\"|" "$file"
        sed -i.bak "s|^postfix_sender_address:.*|postfix_sender_address: \"${CONFIG[contact_sender]:-sender@example.com}\"|" "$file"
        rm -f "${file}.bak"
        info "roles/website/defaults/main.yml updated"
    fi

    # Samba
    if is_selected "samba"; then
        local file="${SCRIPT_DIR}/roles/samba/defaults/main.yml"
        sed -i.bak "s|^samba_user:.*|samba_user: \"${CONFIG[samba_user]:-smbuser}\"|" "$file"
        sed -i.bak "s|^samba_share_name:.*|samba_share_name: \"${CONFIG[samba_share_name]:-storage}\"|" "$file"
        sed -i.bak "s|^samba_host_path:.*|samba_host_path: \"${CONFIG[samba_host_path]:-/mnt/storage}\"|" "$file"
        sed -i.bak "s|^samba_uid:.*|samba_uid: ${CONFIG[samba_uid]:-1100}|" "$file"
        sed -i.bak "s|^samba_gid:.*|samba_gid: ${CONFIG[samba_gid]:-1100}|" "$file"
        rm -f "${file}.bak"
        info "roles/samba/defaults/main.yml updated"
    fi

    # Logging OIDC URLs
    if is_selected "logging" && is_selected "authentik"; then
        local file="${SCRIPT_DIR}/roles/logging/defaults/main.yml"
        local auth_domain="${CONFIG[authentik_domain]:-auth.example.com}"
        sed -i.bak "s|^grafana_oidc_auth_url:.*|grafana_oidc_auth_url: \"https://${auth_domain}/application/o/authorize/\"|" "$file"
        sed -i.bak "s|^grafana_oidc_token_url:.*|grafana_oidc_token_url: \"https://${auth_domain}/application/o/token/\"|" "$file"
        sed -i.bak "s|^grafana_oidc_api_url:.*|grafana_oidc_api_url: \"https://${auth_domain}/application/o/userinfo/\"|" "$file"
        if [[ "${CONFIG[grafana_oidc_enabled]:-false}" == "false" ]]; then
            sed -i.bak "s|^grafana_oidc_enabled:.*|grafana_oidc_enabled: false|" "$file"
        fi
        rm -f "${file}.bak"
        info "roles/logging/defaults/main.yml OIDC URLs updated"
    elif is_selected "logging"; then
        local file="${SCRIPT_DIR}/roles/logging/defaults/main.yml"
        sed -i.bak "s|^grafana_oidc_enabled:.*|grafana_oidc_enabled: false|" "$file"
        rm -f "${file}.bak"
        info "roles/logging/defaults/main.yml OIDC disabled (Authentik not selected)"
    fi
}

apply_vault_files() {
    print_section "Creating vault files"

    # Paperless
    if is_selected "paperless"; then
        local vault_file="${SCRIPT_DIR}/inventory/group_vars/paperless/vault.yml"
        cat > "$vault_file" << EOF
---
paperless_postgres_password: "${CONFIG[paperless_postgres_password]}"
paperless_secret_key: "${CONFIG[paperless_secret_key]}"
paperless_admin_user: "${CONFIG[paperless_admin_user]:-admin}"
paperless_admin_password: "${CONFIG[paperless_admin_password]}"
paperless_admin_email: "${CONFIG[paperless_admin_email]:-admin@example.com}"
paperless_url: "${CONFIG[paperless_url]:-https://paperless.example.com}"
EOF
        if [[ "${CONFIG[paperless_oidc_enabled]:-false}" == "true" ]]; then
            cat >> "$vault_file" << EOF
paperless_oidc_client_id: "${CONFIG[paperless_oidc_client_id]}"
paperless_oidc_client_secret: "${CONFIG[paperless_oidc_client_secret]}"
EOF
        fi
        info "paperless vault.yml created"
    fi

    # Authentik
    if is_selected "authentik"; then
        local vault_file="${SCRIPT_DIR}/inventory/group_vars/authentik/vault.yml"
        cat > "$vault_file" << EOF
---
authentik_postgres_password: "${CONFIG[authentik_postgres_password]}"
authentik_secret_key: "${CONFIG[authentik_secret_key]}"
EOF
        if [[ -n "${CONFIG[authentik_smtp_host]:-}" ]]; then
            cat >> "$vault_file" << EOF
authentik_smtp_host: "${CONFIG[authentik_smtp_host]}"
authentik_smtp_username: "${CONFIG[authentik_smtp_username]}"
authentik_smtp_password: "${CONFIG[authentik_smtp_password]}"
authentik_email_from: "${CONFIG[authentik_email_from]}"
EOF
        fi
        info "authentik vault.yml created"
    fi

    # Docmost
    if is_selected "docmost"; then
        cat > "${SCRIPT_DIR}/inventory/group_vars/docmost/vault.yml" << EOF
---
docmost_app_url: "${CONFIG[docmost_url]:-https://docs.example.com}"
docmost_app_secret: "${CONFIG[docmost_app_secret]}"
docmost_postgres_password: "${CONFIG[docmost_postgres_password]}"
docmost_smtp_host: "${CONFIG[docmost_smtp_host]:-smtp.example.com}"
docmost_smtp_username: "${CONFIG[docmost_smtp_username]:-user@example.com}"
docmost_smtp_password: "${CONFIG[docmost_smtp_password]}"
docmost_mail_from_address: "${CONFIG[docmost_mail_from_address]:-docs@example.com}"
docmost_mail_from_name: "${CONFIG[docmost_mail_from_name]:-Docmost}"
EOF
        info "docmost vault.yml created"
    fi

    # Cloudflared
    if is_selected "cloudflared"; then
        cat > "${SCRIPT_DIR}/inventory/group_vars/cloudflared/vault.yml" << EOF
---
cloudflared_tunnel_token: "${CONFIG[cloudflared_tunnel_token]}"
EOF
        info "cloudflared vault.yml created"
    fi

    # Chronicle (Logging)
    if is_selected "logging"; then
        local vault_file="${SCRIPT_DIR}/inventory/group_vars/chronicle/vault.yml"
        cat > "$vault_file" << EOF
---
grafana_admin_user: "${CONFIG[grafana_admin_user]:-admin}"
grafana_admin_password: "${CONFIG[grafana_admin_password]}"
grafana_domain: "${CONFIG[grafana_domain]:-grafana.example.com}"
EOF
        if [[ "${CONFIG[grafana_oidc_enabled]:-false}" == "true" ]]; then
            cat >> "$vault_file" << EOF
grafana_oidc_client_id: "${CONFIG[grafana_oidc_client_id]}"
grafana_oidc_client_secret: "${CONFIG[grafana_oidc_client_secret]}"
grafana_oidc_issuer: "${CONFIG[grafana_oidc_issuer]}"
EOF
        fi
        info "chronicle vault.yml created"
    fi

    # Samba
    if is_selected "samba"; then
        cat > "${SCRIPT_DIR}/inventory/group_vars/samba/vault.yml" << EOF
---
samba_password: "${CONFIG[samba_password]}"
EOF
        info "samba vault.yml created"
    fi

    # Website
    if is_selected "website"; then
        cat > "${SCRIPT_DIR}/inventory/group_vars/website/vault.yml" << EOF
---
postfix_sasl_password: "${CONFIG[postfix_sasl_password]}"
EOF
        info "website vault.yml created"
    fi
}

encrypt_vault_files() {
    print_section "Encrypting vault files"

    echo "  Choose a vault password to encrypt your secrets."
    echo "  You will need this password every time you run ansible-playbook."
    echo ""

    local vault_pass
    read -rsp "  Vault password: " vault_pass
    echo ""
    read -rsp "  Confirm vault password: " vault_pass_confirm
    echo ""

    if [[ "$vault_pass" != "$vault_pass_confirm" ]]; then
        error "Passwords don't match!"
        exit 1
    fi

    # Save vault password
    local vault_pass_file="${HOME}/.vault_pass"
    echo "$vault_pass" > "$vault_pass_file"
    chmod 600 "$vault_pass_file"
    info "Vault password saved to ${vault_pass_file}"

    # Encrypt all vault files
    for service in "${SELECTED_SERVICES[@]}"; do
        local group="${SERVICE_GROUP_MAP[$service]}"
        local vault_file="${SCRIPT_DIR}/inventory/group_vars/${group}/vault.yml"
        if [[ -f "$vault_file" ]]; then
            ansible-vault encrypt "$vault_file" --vault-password-file "$vault_pass_file" 2>/dev/null
            info "Encrypted: inventory/group_vars/${group}/vault.yml"
        fi
    done
}

remove_unselected() {
    print_section "Removing unselected services"

    for service in "${AVAILABLE_SERVICES[@]}"; do
        if ! is_selected "$service"; then
            local group="${SERVICE_GROUP_MAP[$service]}"

            # Remove role
            if [[ -d "${SCRIPT_DIR}/roles/${service}" ]]; then
                rm -rf "${SCRIPT_DIR}/roles/${service}"
                info "Removed: roles/${service}/"
            fi

            # Remove playbook
            if [[ -f "${SCRIPT_DIR}/playbooks/${service}.yml" ]]; then
                rm -f "${SCRIPT_DIR}/playbooks/${service}.yml"
                info "Removed: playbooks/${service}.yml"
            fi

            # Remove group_vars
            if [[ -d "${SCRIPT_DIR}/inventory/group_vars/${group}" ]]; then
                rm -rf "${SCRIPT_DIR}/inventory/group_vars/${group}"
                info "Removed: inventory/group_vars/${group}/"
            fi
        fi
    done

    # Remove logging-specific files if not selected
    if ! is_selected "logging"; then
        rm -f "${SCRIPT_DIR}/playbooks/diagnose-logging.yml"
        info "Removed: playbooks/diagnose-logging.yml"
    fi

    # Update deploy_all.yml
    apply_deploy_all
}

apply_deploy_all() {
    local deploy_file="${SCRIPT_DIR}/playbooks/deploy_all.yml"

    cat > "$deploy_file" << 'EOF'
---
# Master Playbook: Deploy all selected services
#
# Usage:
#   ansible-playbook playbooks/deploy_all.yml

EOF

    # Add services in dependency order
    local ordered_services=("samba" "cloudflared" "authentik" "logging" "paperless" "docmost" "website")

    for service in "${ordered_services[@]}"; do
        if is_selected "$service"; then
            local name
            case "$service" in
                samba)       name="Samba file server" ;;
                cloudflared) name="Cloudflare Tunnel" ;;
                authentik)   name="Authentik Identity Provider" ;;
                logging)     name="Logging Stack (Loki + Grafana)" ;;
                paperless)   name="Paperless-NGX" ;;
                docmost)     name="Docmost" ;;
                website)     name="Website" ;;
            esac
            cat >> "$deploy_file" << EOF
- name: Deploy ${name}
  ansible.builtin.import_playbook: ${service}.yml

EOF
        fi
    done

    info "playbooks/deploy_all.yml updated"
}

section_apply() {
    print_header "Applying Configuration"

    apply_inventory
    apply_global_vars
    apply_defaults
    apply_vault_files
    encrypt_vault_files
    remove_unselected

    save_answers
    info "Configuration answers saved to .setup-answers.env"
}

# ---------------------------------------------------------------------------
# Section 8: Next Steps
# ---------------------------------------------------------------------------
section_next_steps() {
    print_header "Setup Complete!"

    echo -e "  ${GREEN}Your Ansible homelab is configured and ready to deploy.${NC}"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo ""
    echo "  1. Ensure your LXC containers are running and accessible via SSH"
    echo ""
    echo "  2. Copy your SSH public key to each server:"
    for service in "${SELECTED_SERVICES[@]}"; do
        local host="${SERVICE_HOST_MAP[$service]}"
        local ip="${CONFIG[ip_${service}]}"
        echo "       ssh-copy-id root@${ip}  # ${host}"
    done
    echo ""
    echo "  3. Test connectivity:"
    echo "       ansible lxc_containers -m ping"
    echo ""
    echo "  4. Deploy the security baseline (required first!):"
    echo "       ansible-playbook playbooks/baseline.yml"
    echo ""
    if is_selected "logging"; then
        echo "  5. Deploy the logging stack:"
        echo "       ansible-playbook playbooks/logging.yml"
        echo ""
        echo "  6. Enable log shipping on all containers:"
        echo "       ansible-playbook playbooks/baseline.yml --tags alloy"
        echo ""
        echo "  7. Deploy all services:"
        echo "       ansible-playbook playbooks/deploy_all.yml"
    else
        echo "  5. Deploy all services:"
        echo "       ansible-playbook playbooks/deploy_all.yml"
    fi
    echo ""
    echo -e "  ${BOLD}Useful commands:${NC}"
    echo "    ansible-playbook --syntax-check playbooks/<service>.yml  # Validate"
    echo "    ansible-playbook --check playbooks/<service>.yml         # Dry run"
    echo "    ansible-vault edit inventory/group_vars/<group>/vault.yml # Edit secrets"
    echo ""
    echo -e "  ${BOLD}Re-configure:${NC}"
    echo "    ./setup.sh --reconfigure"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # Parse arguments
    if [[ "${1:-}" == "--reconfigure" ]]; then
        RECONFIGURE=true
        if load_answers; then
            info "Loaded previous configuration from .setup-answers.env"
        else
            warn "No previous configuration found. Starting fresh."
            RECONFIGURE=false
        fi
    fi

    section_welcome
    section_service_selection
    section_network
    section_domains
    section_service_config
    section_summary
    section_apply
    section_next_steps
}

main "$@"
