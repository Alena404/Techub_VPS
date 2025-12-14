#!/bin/bash
# OpenVPN Faux Tunnel Management System v3.0
# Enhanced with SSH account management

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Strict error handling
set -euo pipefail

# Global variables
SCRIPT_DIR="/etc/openvpn/faux-tunnel"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="${SCRIPT_DIR}/clients"
LOG_FILE="/var/log/openvpn-faux-tunnel.log"

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root${NC}" >&2
        exit 1
    fi
}

# Display header
show_header() {
    clear
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}  OpenVPN Faux Tunnel Management System  ${NC}"
    echo -e "${BLUE}            Version 3.0                  ${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
}

# Main menu
show_main_menu() {
    show_header
    echo -e "${YELLOW}Main Menu:${NC}"
    echo "  1. System Initialization"
    echo "  2. OpenVPN Management"
    echo "  3. Client Management"
    echo "  4. SSH Account Management"
    echo "  5. Monitoring & Status"
    echo "  6. Domain Configuration"
    echo "  7. Exit"
    echo ""
}

# OpenVPN submenu
show_openvpn_menu() {
    show_header
    echo -e "${YELLOW}OpenVPN Management:${NC}"
    echo "  1. Start OpenVPN Service"
    echo "  2. Stop OpenVPN Service"
    echo "  3. Restart OpenVPN Service"
    echo "  4. View Service Status"
    echo "  5. Enable at Boot"
    echo "  6. Disable at Boot"
    echo "  7. Back to Main Menu"
    echo ""
}

# Client submenu
show_client_menu() {
    show_header
    echo -e "${YELLOW}Client Management:${NC}"
    echo "  1. Generate New Client"
    echo "  2. List All Clients"
    echo "  3. Revoke Client"
    echo "  4. View Client Configuration"
    echo "  5. Back to Main Menu"
    echo ""
}

# SSH submenu
show_ssh_menu() {
    show_header
    echo -e "${YELLOW}SSH Account Management:${NC}"
    echo "  1. Create SSH Account"
    echo "  2. List SSH Accounts"
    echo "  3. Delete SSH Account"
    echo "  4. Change SSH Password"
    echo "  5. Back to Main Menu"
    echo ""
}

# Monitoring submenu
show_monitoring_menu() {
    show_header
    echo -e "${YELLOW}Monitoring & Status:${NC}"
    echo "  1. System Health Check"
    echo "  2. Connected Clients"
    echo "  3. Bandwidth Usage"
    echo "  4. View Logs"
    echo "  5. Back to Main Menu"
    echo ""
}

# Domain submenu
show_domain_menu() {
    show_header
    echo -e "${YELLOW}Domain Configuration:${NC}"
    echo "  1. View Current Domains"
    echo "  2. Add New Domain"
    echo "  3. Remove Domain"
    echo "  4. Back to Main Menu"
    echo ""
}

# System initialization
initialize_system() {
    show_header
    echo -e "${GREEN}Initializing Faux Tunnel System...${NC}"
    log "INFO" "System initialization started"
    
    # Create directories
    mkdir -p "${SCRIPT_DIR}/clients"
    mkdir -p "${SCRIPT_DIR}/ccd"
    mkdir -p "${SCRIPT_DIR}/backups"
    mkdir -p /var/log
    
    # Install dependencies
    echo -e "${YELLOW}Installing dependencies...${NC}"
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y openvpn easy-rsa iptables-persistent dnsutils net-tools openssh-server
    elif command -v yum &> /dev/null; then
        yum install -y epel-release
        yum install -y openvpn easy-rsa iptables-services bind-utils net-tools openssh-server
    else
        echo -e "${RED}WARNING: Unsupported package manager. Please install OpenVPN manually.${NC}"
    fi
    
    # Setup EasyRSA
    echo -e "${YELLOW}Setting up EasyRSA...${NC}"
    mkdir -p "${EASYRSA_DIR}"
    if [[ -d "/usr/share/easy-rsa/3" ]]; then
        cp -r /usr/share/easy-rsa/3/* "${EASYRSA_DIR}/"
    elif [[ -d "/usr/share/easy-rsa" ]]; then
        cp -r /usr/share/easy-rsa/* "${EASYRSA_DIR}/"
    else
        echo -e "${YELLOW}Installing easy-rsa package...${NC}"
        if command -v apt-get &> /dev/null; then
            apt-get install -y easy-rsa
            cp -r /usr/share/easy-rsa/* "${EASYRSA_DIR}/"
        fi
    fi
    
    # Initialize PKI
    cd "${EASYRSA_DIR}"
    ./easyrsa init-pki
    
    # Create CA
    echo "ca" | ./easyrsa build-ca nopass
    
    # Generate server certificate
    ./easyrsa gen-req server nopass
    echo "yes" | ./easyrsa sign-req server server
    
    # Generate Diffie-Hellman parameters
    ./easyrsa gen-dh
    
    # Generate HMAC key
    openvpn --genkey --secret pki/ta.key
    
    # Create OpenVPN server configuration
    cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/easy-rsa/pki/ta.key 0
auth SHA256
cipher AES-256-CBC
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
server 10.8.0.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
client-to-client
client-config-dir /etc/openvpn/faux-tunnel/ccd
duplicate-cn
keepalive 10 120
persist-key
persist-tun
comp-lzo
verb 3
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
user nobody
group nogroup
management 127.0.0.1 6001
EOF
    
    # Setup IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables NAT
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$PRIMARY_INTERFACE" -j MASQUERADE
    iptables -A INPUT -i tun+ -j ACCEPT
    iptables -A FORWARD -i tun+ -j ACCEPT
    iptables -A FORWARD -o tun+ -j ACCEPT
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    # Create domain configuration
    cat > "${SCRIPT_DIR}/isp_domains.conf" << 'EOF'
# ISP Domain Configuration for Faux Tunneling Lab
zero_rated_domains=mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com
zero_rated_domains_alt=mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com
additional_domains=instagram.com,whatsapp.com
policy_group_social=www.facebook.com,www.ayoba.me,m.facebook.com,instagram.com,whatsapp.com
policy_group_carrier=mtn.cm,nointernet.mtn.cm,mtnonline.com
EOF
    
    # Create client template
    cat > "${SCRIPT_DIR}/client-template.ovpn" << 'EOF'
client
dev tun
proto udp
remote YOUR_SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
comp-lzo
verb 3
<ca>
</ca>
<cert>
</cert>
<key>
</key>
<tls-auth>
</tls-auth>
key-direction 1
EOF
    
    log "INFO" "System initialization completed"
    echo -e "${GREEN}System initialized successfully!${NC}"
    echo ""
    read -p "Press Enter to continue..."
}

# Generate client certificate and configuration
generate_client() {
    show_header
    echo -e "${GREEN}Generate New Client${NC}"
    echo ""
    
    read -p "Enter client name: " client_name
    
    if [[ -z "$client_name" ]]; then
        echo -e "${RED}ERROR: Client name is required${NC}" >&2
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${YELLOW}Generating client configuration for: $client_name${NC}"
    log "INFO" "Generating client: $client_name"
    
    cd "${EASYRSA_DIR}"
    
    # Generate client certificate
    ./easyrsa gen-req "$client_name" nopass
    echo "yes" | ./easyrsa sign-req client "$client_name"
    
    # Create client directory
    mkdir -p "${CLIENT_DIR}/$client_name"
    
    # Create client config with embedded certificates
    local client_config="${CLIENT_DIR}/$client_name/$client_name.ovpn"
    cp "${SCRIPT_DIR}/client-template.ovpn" "$client_config"
    
    # Embed certificates
    sed -i '/<ca>/r'"${EASYRSA_DIR}"'/pki/ca.crt' "$client_config"
    sed -i '/<cert>/r'"${EASYRSA_DIR}"'/pki/issued/'"$client_name"'.crt' "$client_config"
    sed -i '/<key>/r'"${EASYRSA_DIR}"'/pki/private/'"$client_name"'.key' "$client_config"
    sed -i '/<tls-auth>/r'"${EASYRSA_DIR}"'/pki/ta.key' "$client_config"
    
    # Replace server IP in config
    SERVER_IP=$(hostname -I | awk '{print $1}')
    sed -i "s/YOUR_SERVER_IP/$SERVER_IP/g" "$client_config"
    
    echo ""
    echo -e "${GREEN}Client configuration created successfully!${NC}"
    echo "Configuration file: $client_config"
    echo ""
    read -p "Press Enter to continue..."
}

# List all clients
list_clients() {
    show_header
    echo -e "${GREEN}Client List${NC}"
    echo ""
    
    if [[ ! -d "${CLIENT_DIR}" ]] || [[ -z "$(ls -A "${CLIENT_DIR}")" ]]; then
        echo "No clients found."
    else
        echo "Available clients:"
        for client_dir in "${CLIENT_DIR}"/*/; do
            if [[ -d "$client_dir" ]]; then
                client_name=$(basename "$client_dir")
                echo "  - $client_name"
            fi
        done
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Revoke client
revoke_client() {
    show_header
    echo -e "${GREEN}Revoke Client${NC}"
    echo ""
    
    list_clients_no_pause
    
    echo ""
    read -p "Enter client name to revoke: " client_name
    
    if [[ -z "$client_name" ]]; then
        echo -e "${RED}ERROR: Client name is required${NC}" >&2
        read -p "Press Enter to continue..."
        return 1
    fi
    
    if [[ ! -d "${CLIENT_DIR}/$client_name" ]]; then
        echo -e "${RED}Client not found: $client_name${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${YELLOW}Revoking client: $client_name${NC}"
    log "INFO" "Revoking client: $client_name"
    
    cd "${EASYRSA_DIR}"
    
    # Revoke certificate
    echo "yes" | ./easyrsa revoke "$client_name"
    
    # Generate CRL
    ./easyrsa gen-crl
    
    # Copy CRL to OpenVPN directory
    cp pki/crl.pem /etc/openvpn/
    
    # Add crl-verify to server config if not already present
    if ! grep -q "crl-verify" /etc/openvpn/server.conf; then
        echo "crl-verify /etc/openvpn/crl.pem" >> /etc/openvpn/server.conf
    fi
    
    # Remove client directory
    rm -rf "${CLIENT_DIR}/$client_name"
    
    echo -e "${GREEN}Client revoked successfully!${NC}"
    echo ""
    read -p "Press Enter to continue..."
}

# View client config
view_client_config() {
    show_header
    echo -e "${GREEN}View Client Configuration${NC}"
    echo ""
    
    list_clients_no_pause
    
    echo ""
    read -p "Enter client name: " client_name
    
    if [[ -z "$client_name" ]]; then
        echo -e "${RED}ERROR: Client name is required${NC}" >&2
        read -p "Press Enter to continue..."
        return 1
    fi
    
    local config_file="${CLIENT_DIR}/$client_name/$client_name.ovpn"
    
    if [[ ! -f "$config_file" ]]; then
        echo -e "${RED}Client configuration not found: $client_name${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo ""
    echo "Client configuration for: $client_name"
    echo "===================================="
    cat "$config_file"
    echo "===================================="
    echo ""
    echo -e "${GREEN}To copy this configuration:${NC}"
    echo "cat $config_file"
    echo ""
    read -p "Press Enter to continue..."
}

# List clients without pause (for internal use)
list_clients_no_pause() {
    if [[ ! -d "${CLIENT_DIR}" ]] || [[ -z "$(ls -A "${CLIENT_DIR}")" ]]; then
        echo "No clients found."
    else
        echo "Available clients:"
        for client_dir in "${CLIENT_DIR}"/*/; do
            if [[ -d "$client_dir" ]]; then
                client_name=$(basename "$client_dir")
                echo "  - $client_name"
            fi
        done
    fi
}

# Create SSH account
create_ssh_account() {
    show_header
    echo -e "${GREEN}Create SSH Account${NC}"
    echo ""
    
    read -p "Enter username: " username
    read -s -p "Enter password: " password
    echo ""
    read -s -p "Confirm password: " password_confirm
    echo ""
    
    if [[ -z "$username" ]]; then
        echo -e "${RED}ERROR: Username is required${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    if [[ "$password" != "$password_confirm" ]]; then
        echo -e "${RED}ERROR: Passwords do not match${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    if [[ -z "$password" ]]; then
        echo -e "${RED}ERROR: Password is required${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        echo -e "${YELLOW}User already exists. Updating password...${NC}"
        echo "$username:$password" | chpasswd
    else
        # Create user
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        
        # Add to sudo group if it exists
        if getent group sudo > /dev/null 2>&1; then
            usermod -aG sudo "$username"
        elif getent group wheel > /dev/null 2>&1; then
            usermod -aG wheel "$username"
        fi
    fi
    
    # Display connection details
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    
    echo ""
    echo -e "${GREEN}SSH Account Created Successfully!${NC}"
    echo "=================================="
    echo "Username: $username"
    echo "Password: $password"
    echo "Server IP: $SERVER_IP"
    echo "SSH Port: $SSH_PORT"
    echo "=================================="
    echo ""
    echo -e "${YELLOW}Connection command:${NC}"
    echo "ssh $username@$SERVER_IP -p $SSH_PORT"
    echo ""
    echo -e "${GREEN}IMPORTANT: Save this information now!${NC}"
    echo ""
    log "INFO" "SSH account created: $username"
    
    read -p "Press Enter to continue..."
}

# List SSH accounts
list_ssh_accounts() {
    show_header
    echo -e "${GREEN}SSH Accounts${NC}"
    echo ""
    
    echo "SSH accounts on this system:"
    echo "============================"
    grep -vE 'nologin|false|sync|shutdown|halt' /etc/passwd | grep '/home' | cut -d: -f1
    echo ""
    
    echo "Active SSH sessions:"
    echo "===================="
    who | grep -v 'tty\|pts' || echo "No active SSH sessions"
    echo ""
    
    read -p "Press Enter to continue..."
}

# Delete SSH account
delete_ssh_account() {
    show_header
    echo -e "${GREEN}Delete SSH Account${NC}"
    echo ""
    
    # List current users
    echo "Current system users:"
    grep -vE 'nologin|false|sync|shutdown|halt' /etc/passwd | grep '/home' | cut -d: -f1 | nl -v1
    
    echo ""
    read -p "Enter username to delete: " username
    
    if [[ -z "$username" ]]; then
        echo -e "${RED}ERROR: Username is required${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}User not found: $username${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${YELLOW}WARNING: This will permanently delete user $username and their home directory${NC}"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        userdel -r "$username" 2>/dev/null || true
        echo -e "${GREEN}User $username deleted successfully${NC}"
        log "INFO" "SSH account deleted: $username"
    else
        echo "Deletion cancelled."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Change SSH password
change_ssh_password() {
    show_header
    echo -e "${GREEN}Change SSH Password${NC}"
    echo ""
    
    # List current users
    echo "Current system users:"
    grep -vE 'nologin|false|sync|shutdown|halt' /etc/passwd | grep '/home' | cut -d: -f1 | nl -v1
    
    echo ""
    read -p "Enter username: " username
    
    if [[ -z "$username" ]]; then
        echo -e "${RED}ERROR: Username is required${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}User not found: $username${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    read -s -p "Enter new password: " password
    echo ""
    read -s -p "Confirm new password: " password_confirm
    echo ""
    
    if [[ "$password" != "$password_confirm" ]]; then
        echo -e "${RED}ERROR: Passwords do not match${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    if [[ -z "$password" ]]; then
        echo -e "${RED}ERROR: Password is required${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo "$username:$password" | chpasswd
    echo -e "${GREEN}Password changed successfully for user: $username${NC}"
    log "INFO" "SSH password changed: $username"
    
    echo ""
    read -p "Press Enter to continue..."
}

# Start OpenVPN service
start_service() {
    show_header
    echo -e "${GREEN}Starting OpenVPN Service...${NC}"
    
    if systemctl start openvpn@server; then
        echo -e "${GREEN}OpenVPN service started successfully${NC}"
        log "INFO" "OpenVPN service started"
    else
        echo -e "${RED}Failed to start OpenVPN service${NC}"
        log "ERROR" "Failed to start OpenVPN service"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Stop OpenVPN service
stop_service() {
    show_header
    echo -e "${GREEN}Stopping OpenVPN Service...${NC}"
    
    if systemctl stop openvpn@server; then
        echo -e "${GREEN}OpenVPN service stopped successfully${NC}"
        log "INFO" "OpenVPN service stopped"
    else
        echo -e "${RED}Failed to stop OpenVPN service${NC}"
        log "ERROR" "Failed to stop OpenVPN service"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Restart OpenVPN service
restart_service() {
    show_header
    echo -e "${GREEN}Restarting OpenVPN Service...${NC}"
    
    if systemctl restart openvpn@server; then
        echo -e "${GREEN}OpenVPN service restarted successfully${NC}"
        log "INFO" "OpenVPN service restarted"
    else
        echo -e "${RED}Failed to restart OpenVPN service${NC}"
        log "ERROR" "Failed to restart OpenVPN service"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# View service status
service_status() {
    show_header
    echo -e "${GREEN}OpenVPN Service Status${NC}"
    echo ""
    
    systemctl status openvpn@server --no-pager
    
    echo ""
    read -p "Press Enter to continue..."
}

# Enable service at boot
enable_service() {
    show_header
    echo -e "${GREEN}Enabling OpenVPN Service at Boot...${NC}"
    
    if systemctl enable openvpn@server; then
        echo -e "${GREEN}OpenVPN service enabled at boot${NC}"
        log "INFO" "OpenVPN service enabled at boot"
    else
        echo -e "${RED}Failed to enable OpenVPN service at boot${NC}"
        log "ERROR" "Failed to enable OpenVPN service at boot"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Disable service at boot
disable_service() {
    show_header
    echo -e "${GREEN}Disabling OpenVPN Service at Boot...${NC}"
    
    if systemctl disable openvpn@server; then
        echo -e "${GREEN}OpenVPN service disabled at boot${NC}"
        log "INFO" "OpenVPN service disabled at boot"
    else
        echo -e "${RED}Failed to disable OpenVPN service at boot${NC}"
        log "ERROR" "Failed to disable OpenVPN service at boot"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# System health check
health_check() {
    show_header
    echo -e "${GREEN}System Health Check${NC}"
    echo ""
    
    echo "=== System Status ==="
    echo "Uptime: $(uptime)"
    echo "Load average: $(uptime | awk -F'load average:' '{print $2}')"
    echo ""
    
    echo "=== OpenVPN Status ==="
    if systemctl is-active --quiet openvpn@server; then
        echo -e "${GREEN}✓ OpenVPN service is running${NC}"
    else
        echo -e "${RED}✗ OpenVPN service is not running${NC}"
    fi
    
    echo ""
    echo "=== Network Interfaces ==="
    ip link show | grep -E '^[0-9]+: [a-z]' | awk '{print $2}' | sed 's/://'
    
    echo ""
    echo "=== Disk Usage ==="
    df -h | grep -E 'Filesystem|/dev/' | column -t
    
    echo ""
    echo "=== Memory Usage ==="
    free -h
    
    echo ""
    echo "=== Connected Clients ==="
    if [[ -f "/var/log/openvpn-status.log" ]]; then
        grep -c "CLIENT_LIST" /var/log/openvpn-status.log 2>/dev/null || echo "0"
    else
        echo "0"
    fi
    
    log "INFO" "Health check performed"
    echo ""
    read -p "Press Enter to continue..."
}

# View domains
view_domains() {
    show_header
    echo -e "${GREEN}Current Domain Configuration${NC}"
    echo ""
    
    if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        cat "${SCRIPT_DIR}/isp_domains.conf"
    else
        echo "Domain configuration file not found."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Main execution loop
main() {
    check_root
    
    while true; do
        show_main_menu
        read -p "Select option (1-7): " main_choice
        
        case $main_choice in
            1)
                initialize_system
                ;;
            2)
                while true; do
                    show_openvpn_menu
                    read -p "Select option (1-7): " openvpn_choice
                    
                    case $openvpn_choice in
                        1) start_service ;;
                        2) stop_service ;;
                        3) restart_service ;;
                        4) service_status ;;
                        5) enable_service ;;
                        6) disable_service ;;
                        7) break ;;
                        *) 
                            echo -e "${RED}Invalid option${NC}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            3)
                while true; do
                    show_client_menu
                    read -p "Select option (1-5): " client_choice
                    
                    case $client_choice in
                        1) generate_client ;;
                        2) list_clients ;;
                        3) revoke_client ;;
                        4) view_client_config ;;
                        5) break ;;
                        *) 
                            echo -e "${RED}Invalid option${NC}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            4)
                while true; do
                    show_ssh_menu
                    read -p "Select option (1-5): " ssh_choice
                    
                    case $ssh_choice in
                        1) create_ssh_account ;;
                        2) list_ssh_accounts ;;
                        3) delete_ssh_account ;;
                        4) change_ssh_password ;;
                        5) break ;;
                        *) 
                            echo -e "${RED}Invalid option${NC}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            5)
                while true; do
                    show_monitoring_menu
                    read -p "Select option (1-5): " monitoring_choice
                    
                    case $monitoring_choice in
                        1) health_check ;;
                        2) 
                            show_header
                            echo -e "${GREEN}Connected Clients${NC}"
                            echo ""
                            if [[ -f "/var/log/openvpn-status.log" ]]; then
                                grep "CLIENT_LIST" /var/log/openvpn-status.log | tail -10 || echo "No clients connected"
                            else
                                echo "OpenVPN status log not found."
                            fi
                            echo ""
                            read -p "Press Enter to continue..."
                            ;;
                        3) 
                            show_header
                            echo -e "${GREEN}Bandwidth Usage${NC}"
                            echo ""
                            if command -v ifconfig &> /dev/null; then
                                ifconfig tun0 2>/dev/null || echo "tun0 interface not found"
                            else
                                echo "ifconfig command not available"
                            fi
                            echo ""
                            read -p "Press Enter to continue..."
                            ;;
                        4) 
                            show_header
                            echo -e "${GREEN}Recent Logs${NC}"
                            echo ""
                            tail -20 "${LOG_FILE}" 2>/dev/null || echo "Log file not found"
                            echo ""
                            read -p "Press Enter to continue..."
                            ;;
                        5) break ;;
                        *) 
                            echo -e "${RED}Invalid option${NC}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            6)
                while true; do
                    show_domain_menu
                    read -p "Select option (1-4): " domain_choice
                    
                    case $domain_choice in
                        1) view_domains ;;
                        2) 
                            echo -e "${RED}Domain addition not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        3) 
                            echo -e "${RED}Domain removal not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        4) break ;;
                        *) 
                            echo -e "${RED}Invalid option${NC}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            7)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
}

# Run main function
main "$@"
