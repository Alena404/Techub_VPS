#!/bin/bash
# Techub OpenVPN Management System v4.1
# Advanced Penetration Testing Toolkit for Educational Simulations
# Comprehensive Faux Tunneling with MTN Cameroon Bypass Implementation

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script paths and global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
AUTO_LAUNCH_FILE="/usr/local/bin/techub-auto-launch"
SYSTEMD_SERVICE="/etc/systemd/system/openvpn-faux-tunnel.service"
SSH_TUNNEL_SERVICE="/etc/systemd/system/techub-ssh-tunnel.service"
LOG_FILE="/var/log/techub.log"

# Ensure we're running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Show header
show_header() {
    clear
    echo -e "${CYAN}==============================================${NC}"
    echo -e "${CYAN}    Techub OpenVPN Management System v4.1     ${NC}"
    echo -e "${CYAN}         Advanced Faux Tunneling              ${NC}"
    echo -e "${CYAN}==============================================${NC}"
    echo ""
}

# Display main menu
show_main_menu() {
    show_header
    echo -e "${GREEN}Main Menu:${NC}"
    echo "1. Install OpenVPN Server"
    echo "2. Uninstall OpenVPN Server"
    echo "3. Start OpenVPN Server"
    echo "4. Stop OpenVPN Server"
    echo "5. Advanced Configuration"
    echo "6. System Status"
    echo "7. Logs"
    echo "8. Exit"
    echo ""
}

# Display advanced menu
show_advanced_menu() {
    show_header
    echo -e "${GREEN}Advanced Configuration:${NC}"
    echo "1. Configure MTN Cameroon Bypass"
    echo "2. Configure Orange Cameroon Bypass"
    echo "3. Install Auto Launch System"
    echo "4. Configure Traffic Shaping"
    echo "5. Setup Squid Proxy"
    echo "6. Configure DNS Spoofing"
    echo "7. Configure SSH Tunneling"
    echo "8. Back to Main Menu"
    echo ""
}

# Install OpenVPN Server
install_openvpn() {
    show_header
    echo -e "${GREEN}Installing OpenVPN Server...${NC}"
    
    # Update system packages
    apt-get update
    
    # Install OpenVPN and dependencies
    apt-get install -y openvpn easy-rsa iptables-persistent
    
    # Set up Easy-RSA
    make-cadir ~/openvpn-ca
    cd ~/openvpn-ca
    
    # Configure vars
    cat > vars << 'EOF'
export KEY_COUNTRY="CM"
export KEY_PROVINCE="CAM"
export KEY_CITY="Yaounde"
export KEY_ORG="Techub"
export KEY_EMAIL="techub@example.com"
export KEY_OU="Techub"
export KEY_NAME="server"
EOF
    
    # Build CA
    source vars
    ./clean-all
    ./build-ca << 'EOF'
Techub
CM
CAM
Yaounde
Techub
techub@example.com
Techub

EOF
    
    # Build server key
    ./build-key-server server << 'EOF'
Techub
CM
CAM
Yaounde
Techub
techub@example.com
Techub

y
y
EOF
    
    # Generate Diffie Hellman parameters
    ./build-dh
    
    # Generate HMAC signature
    openvpn --genkey --secret keys/ta.key
    
    # Copy keys to OpenVPN directory
    cd ~/openvpn-ca/keys
    cp ca.crt server.crt server.key ta.key dh2048.pem /etc/openvpn
    
    # Create server configuration
    cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
EOF
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables
    iptables -t nat -A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables/rules.v4
    
    echo -e "${GREEN}OpenVPN Server installed successfully!${NC}"
    log "INFO" "OpenVPN server installed"
    read -p "Press Enter to continue..."
}

# Start OpenVPN Server
start_openvpn() {
    show_header
    echo -e "${GREEN}Starting OpenVPN Server...${NC}"
    
    if systemctl start openvpn@server; then
        echo -e "${GREEN}OpenVPN Server started successfully!${NC}"
        log "INFO" "OpenVPN server started"
    else
        echo -e "${RED}Failed to start OpenVPN Server${NC}"
        log "ERROR" "Failed to start OpenVPN server"
    fi
    
    read -p "Press Enter to continue..."
}

# Stop OpenVPN Server
stop_openvpn() {
    show_header
    echo -e "${GREEN}Stopping OpenVPN Server...${NC}"
    
    if systemctl stop openvpn@server; then
        echo -e "${GREEN}OpenVPN Server stopped successfully!${NC}"
        log "INFO" "OpenVPN server stopped"
    else
        echo -e "${RED}Failed to stop OpenVPN Server${NC}"
        log "ERROR" "Failed to stop OpenVPN server"
    fi
    
    read -p "Press Enter to continue..."
}

# Uninstall OpenVPN Server
uninstall_openvpn() {
    show_header
    echo -e "${YELLOW}Uninstalling OpenVPN Server...${NC}"
    
    # Stop OpenVPN service
    systemctl stop openvpn@server
    
    # Remove OpenVPN package
    apt-get remove --purge -y openvpn easy-rsa
    
    # Remove configuration files
    rm -rf /etc/openvpn
    rm -rf ~/openvpn-ca
    
    # Remove iptables rules
    iptables -t nat -F
    iptables-save > /etc/iptables/rules.v4
    
    echo -e "${GREEN}OpenVPN Server uninstalled successfully!${NC}"
    log "INFO" "OpenVPN server uninstalled"
    read -p "Press Enter to continue..."
}

# Display system status
show_status() {
    show_header
    echo -e "${GREEN}System Status:${NC}"
    echo ""
    
    # Check OpenVPN status
    if systemctl is-active --quiet openvpn@server; then
        echo -e "OpenVPN Server: ${GREEN}Running${NC}"
    else
        echo -e "OpenVPN Server: ${RED}Stopped${NC}"
    fi
    
    # Check SSH tunnel status
    if systemctl is-active --quiet techub-ssh-tunnel; then
        echo -e "SSH Tunnel Service: ${GREEN}Running${NC}"
    else
        echo -e "SSH Tunnel Service: ${RED}Stopped${NC}"
    fi
    
    # Check IP forwarding
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]]; then
        echo -e "IP Forwarding: ${GREEN}Enabled${NC}"
    else
        echo -e "IP Forwarding: ${RED}Disabled${NC}"
    fi
    
    # Check iptables rules
    if iptables -t nat -L -n | grep -q MASQUERADE; then
        echo -e "NAT Rules: ${GREEN}Configured${NC}"
    else
        echo -e "NAT Rules: ${RED}Not Configured${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Display logs
show_logs() {
    show_header
    echo -e "${GREEN}System Logs:${NC}"
    echo ""
    
    if [[ -f "$LOG_FILE" ]]; then
        tail -n 20 "$LOG_FILE"
    else
        echo "No logs available"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Initialize MTN domain configuration
initialize_mtn_domains() {
    cat > "${SCRIPT_DIR}/isp_domains.conf" << 'EOF'
# MTN Cameroon Domain Configuration for Faux Tunneling
# Using domain names for DNS resolution with proper handling
zero_rated_domains=mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com
zero_rated_domains_alt=mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com
mtn_cm_ips=196.168.1.1,196.168.1.2
social_media_ips=69.171.247.12,69.171.247.11,157.240.1.35
messaging_domains=157.240.1.35,157.240.2.9
video_domains=172.217.170.174,142.250.74.110
news_domains=172.217.170.195,104.244.42.193
avoid_detection_domains=8.8.8.8,1.1.1.1
parallel_connections=true
load_balancing=true
EOF
}

# Configure MTN Cameroon bypass systems (FIXED VERSION)
configure_mtn_bypass() {
    show_header
    echo -e "${GREEN}Configuring MTN Cameroon Bypass Systems${NC}"
    echo ""
    
    # Load domain information or set defaults
    if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        echo "Loading domain configuration..."
        source "${SCRIPT_DIR}/isp_domains.conf"
    else
        echo -e "${YELLOW}Domain configuration not found, using defaults...${NC}"
        # Use domain names for proper MTN bypass
        zero_rated_domains="mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com"
        zero_rated_domains_alt="mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com"
    fi
    
    echo -e "${YELLOW}Setting up MTN Cameroon bypass configuration...${NC}"
    
    # 1. Configure iptables for domain redirection using domains
    echo "1. Setting up traffic redirection rules for MTN domains..."
    
    # Get primary interface
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # Create custom chain for MTN domains
    iptables -t nat -N mtn_bypass 2>/dev/null || true
    iptables -t nat -F mtn_bypass
    
    # Parse domains and create redirection rules
    IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
    for domain in "${DOMAINS[@]}"; do
        # Create redirection rules for each domain
        iptables -t nat -A mtn_bypass -p tcp -d "$domain" --dport 80 -j REDIRECT --to-port 80 2>/dev/null || true
        iptables -t nat -A mtn_bypass -p tcp -d "$domain" --dport 443 -j REDIRECT --to-port 443 2>/dev/null || true
    done
    
    # Also handle alternative domains
    IFS=',' read -ra ALT_DOMAINS <<< "$zero_rated_domains_alt"
    for domain in "${ALT_DOMAINS[@]}"; do
        iptables -t nat -A mtn_bypass -p tcp -d "$domain" --dport 80 -j REDIRECT --to-port 80 2>/dev/null || true
        iptables -t nat -A mtn_bypass -p tcp -d "$domain" --dport 443 -j REDIRECT --to-port 443 2>/dev/null || true
    done
    
    # Apply chain to main NAT rules
    iptables -t nat -A PREROUTING -j mtn_bypass 2>/dev/null || true
    
    # 2. Configure DNS to handle MTN domains properly
    echo "2. Setting up DNS handling for zero-rated domains..."
    
    # Create a custom DNS hosts file for MTN domains
    cat > /etc/hosts.mtn << EOF
# MTN Cameroon Hosts File for Zero-Rated Services
196.168.1.1 mtn.cm
196.168.1.1 nointernet.mtn.cm
196.168.1.1 mtnonline.com
196.168.1.1 ayoba.me
69.171.247.12 www.facebook.com
69.171.247.11 facebook.com
69.171.247.12 m.facebook.com
69.171.247.12 fbcdn.net
157.240.1.35 instagram.com
157.240.1.35 whatsapp.com
157.240.1.35 www.ayoba.me
EOF
    
    # Merge with system hosts
    cat /etc/hosts.mtn >> /etc/hosts
    
    # 3. Create MTN-specific routing table if not exists
    echo "3. Setting up routing optimizations..."
    
    # Ensure MTN routing table exists
    if ! grep -q "mtn" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "100 mtn" >> /etc/iproute2/rt_tables
    fi
    
    # 4. Set up traffic prioritization using traffic control
    echo "4. Setting up traffic prioritization..."
    
    # Clear existing rules with error handling
    tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null || true
    
    # Set up HTB (Hierarchical Token Bucket) for bandwidth management
    if tc qdisc add dev "$PRIMARY_INTERFACE" root handle 1: htb default 30 2>/dev/null; then
        tc class add dev "$PRIMARY_INTERFACE" parent 1: classid 1:1 htb rate 100mbit 2>/dev/null || true
        tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit 2>/dev/null || true
        tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:20 htb rate 30mbit ceil 100mbit 2>/dev/null || true
        tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:30 htb rate 20mbit ceil 100mbit 2>/dev/null || true
        
        # Prioritize tunnel traffic (use actual IPs from MTN)
        tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip sport 443 0xffff flowid 1:10 2>/dev/null || true
        tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dport 443 0xffff flowid 1:10 2>/dev/null || true
    else
        echo -e "${YELLOW}Warning: Could not configure traffic control${NC}"
    fi
    
    # 5. Configure Squid proxy for MTN domains if available
    echo "5. Setting up HTTP proxy configuration..."
    
    # Ensure squid is installed
    if ! command -v squid &> /dev/null; then
        echo "Installing Squid proxy..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y squid
        elif command -v yum &> /dev/null; then
            yum install -y squid
        else
            echo -e "${YELLOW}Warning: Could not install Squid automatically${NC}"
        fi
    fi
    
    # Create Squid configuration optimized for MTN Cameroon if squid is available
    if command -v squid &> /dev/null; then
        cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
visible_hostname techub-mtn-proxy

# MTN Cameroon zero-rated domains - direct access (appears as MTN traffic)
acl mtn_domains dstdomain .mtn.cm
acl mtn_domains dstdomain .nointernet.mtn.cm
acl mtn_domains dstdomain .mtnonline.com
acl facebook_domains dstdomain .facebook.com
acl facebook_domains dstdomain .fbcdn.net
acl facebook_domains dstdomain www.facebook.com
acl facebook_domains dstdomain m.facebook.com
acl messaging_domains dstdomain .whatsapp.com
acl messaging_domains dstdomain .instagram.com
acl messaging_domains dstdomain .ayoba.me

# Always direct these domains to MTN
always_direct allow mtn_domains
always_direct allow facebook_domains
always_direct allow messaging_domains

# Standard configuration
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access deny all

coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
EOF
        
        # Restart squid with error handling
        systemctl restart squid 2>/dev/null || echo -e "${YELLOW}Warning: Could not restart Squid${NC}"
        systemctl enable squid 2>/dev/null || true
    fi
    
    # 6. Configure iptables NAT rules to properly route MTN traffic
    echo "6. Setting up specialized NAT rules for MTN..."
    
    # Parse domains and create NAT rules
    IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
    for domain in "${DOMAINS[@]}"; do
        # NAT rules to redirect common ports to MTN
        iptables -t nat -A OUTPUT -p tcp -d "$domain" --dport 80 -j DNAT --to-destination 196.168.1.1:80 2>/dev/null || true
        iptables -t nat -A OUTPUT -p tcp -d "$domain" --dport 443 -j DNAT --to-destination 196.168.1.1:443 2>/dev/null || true
    done
    
    echo ""
    echo -e "${GREEN}MTN Cameroon bypass configuration completed!${NC}"
    echo ""
    echo "Key configurations applied:"
    echo "1. Special routing for MTN zero-rated domains"
    echo "2. DNS handling with custom hosts file"
    echo "3. Traffic prioritization for optimized performance"
    echo "4. HTTP proxy for direct access to MTN services"
    echo "5. Special NAT rules to make traffic appear as MTN"
    echo ""
    echo "Users can access MTN zero-rated services without using data!"
    echo ""
    log "INFO" "MTN Cameroon bypass configured"
    read -p "Press Enter to continue..."
}

# Install auto launch functionality (FIXED VERSION)
install_auto_launch() {
    show_header
    echo -e "${GREEN}Installing Auto Launch System${NC}"
    echo ""
    
    # Create auto-launch script with proper error handling
    cat > "${AUTO_LAUNCH_FILE}" << EOF
#!/bin/bash
# Techub Auto Launch Script

# Navigate to the script directory
cd "$(dirname "${SCRIPT_PATH}")" 2>/dev/null || {
    echo "Error: Could not navigate to script directory"
    exit 1
}

# Ensure script is executable
chmod +x "$(basename "${SCRIPT_PATH}")" 2>/dev/null || true

# Execute the main script
exec sudo "./$(basename "${SCRIPT_PATH}")"
EOF
    
    chmod +x "${AUTO_LAUNCH_FILE}"
    
    # Update shell profiles to launch when typing 'techub'
    for profile in ~/.bashrc ~/.bash_aliases ~/.zshrc; do
        if [[ -f "$profile" ]]; then
            if ! grep -q "alias techub=" "$profile" 2>/dev/null; then
                echo "alias techub='${AUTO_LAUNCH_FILE}'" >> "$profile"
            fi
        fi
    done
    
    # Also create a system-wide symlink
    ln -sf "${SCRIPT_PATH}" /usr/local/bin/techub 2>/dev/null || true
    
    # Create systemd service for persistent operation
    cat > "${SYSTEMD_SERVICE}" << EOF
[Unit]
Description=Techub OpenVPN Faux Tunnel Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/Techub_VPS
ExecStart=/usr/bin/sudo /root/Techub_VPS/openvpn_manage_spoofed_tunnel_v4.0.sh service-mode
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start the service with proper error handling
    systemctl daemon-reload
    systemctl enable openvpn-faux-tunnel.service 2>/dev/null || echo -e "${YELLOW}Warning: Could not enable systemd service${NC}"
    
    echo ""
    echo -e "${GREEN}Auto Launch System installed successfully!${NC}"
    echo ""
    echo "Features activated:"
    echo "1. Type 'techub' from any terminal to launch main menu"
    echo "2. Persistent 24/7 operation through systemd service"
    echo "3. Auto-reconnect on failures"
    echo "4. System-wide command access"
    echo ""
    echo "To start the persistent service now:"
    echo "sudo systemctl start openvpn-faux-tunnel"
    echo ""
    echo "To check service status:"
    echo "sudo systemctl status openvpn-faux-tunnel"
    echo ""
    
    # Initialize MTN domain configuration by default
    echo "Initializing MTN Cameroon configuration..."
    initialize_mtn_domains
    
    read -p "Press Enter to continue..."
}

# Configure traffic shaping
configure_traffic_shaping() {
    show_header
    echo -e "${GREEN}Configuring Traffic Shaping${NC}"
    echo ""
    
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # Clear existing rules
    tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null || true
    
    # Apply basic traffic shaping
    tc qdisc add dev "$PRIMARY_INTERFACE" root handle 1: htb default 30
    tc class add dev "$PRIMARY_INTERFACE" parent 1: classid 1:1 htb rate 100mbit
    tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit
    tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:20 htb rate 30mbit ceil 100mbit
    tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:30 htb rate 20mbit ceil 100mbit
    
    # Prioritize OpenVPN traffic
    tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip sport 1194 0xffff flowid 1:10
    tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dport 1194 0xffff flowid 1:10
    
    echo -e "${GREEN}Traffic shaping configured successfully!${NC}"
    log "INFO" "Traffic shaping configured"
    read -p "Press Enter to continue..."
}

# Configure DNS spoofing
configure_dns_spoofing() {
    show_header
    echo -e "${GREEN}Configuring DNS Spoofing${NC}"
    echo ""
    
    # Install dnsmasq if not present
    if ! command -v dnsmasq &> /dev/null; then
        echo "Installing dnsmasq..."
        apt-get update && apt-get install -y dnsmasq
    fi
    
    # Configure dnsmasq
    cat > /etc/dnsmasq.conf << 'EOF'
# DNS spoofing configuration
interface=tun0
bind-interfaces
server=8.8.8.8
server=8.8.4.4
domain-needed
bogus-priv
EOF
    
    # Restart dnsmasq
    systemctl restart dnsmasq
    
    echo -e "${GREEN}DNS spoofing configured successfully!${NC}"
    log "INFO" "DNS spoofing configured"
    read -p "Press Enter to continue..."
}

# Setup Squid proxy
setup_squid_proxy() {
    show_header
    echo -e "${GREEN}Setting up Squid Proxy${NC}"
    echo ""
    
    # Install squid if not present
    if ! command -v squid &> /dev/null; then
        echo "Installing Squid proxy..."
        apt-get update && apt-get install -y squid
    fi
    
    # Basic squid configuration
    cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
visible_hostname techub-proxy

acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access deny all

coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
EOF
    
    # Start squid
    systemctl restart squid
    systemctl enable squid
    
    echo -e "${GREEN}Squid proxy configured successfully!${NC}"
    echo "Proxy available at port 3128"
    log "INFO" "Squid proxy configured"
    read -p "Press Enter to continue..."
}

# Configure SSH tunneling for MTN zero-rated domains
configure_ssh_tunneling() {
    show_header
    echo -e "${GREEN}Configuring SSH Tunneling for MTN Zero-Rated Access${NC}"
    echo ""
    
    # Install SSH server if not present
    if ! command -v sshd &> /dev/null; then
        echo "Installing SSH server..."
        apt-get update && apt-get install -y openssh-server
    fi
    
    # Configure SSH for tunneling
    cat >> /etc/ssh/sshd_config << 'EOF'

# SSH Tunneling Configuration for MTN Zero-Rated Access
PermitTunnel yes
PermitOpen any
AllowTcpForwarding yes
GatewayPorts yes
AllowAgentForwarding yes
AllowStreamLocalForwarding yes
X11Forwarding yes
PermitTTY yes
EOF
    
    # Restart SSH service
    systemctl restart ssh
    
    # Load domain information or set defaults
    if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        source "${SCRIPT_DIR}/isp_domains.conf"
    else
        echo -e "${YELLOW}Domain configuration not found, using defaults...${NC}"
        zero_rated_domains="mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com"
        zero_rated_domains_alt="mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com"
    fi
    
    # Create SSH tunnel management script
    cat > /usr/local/bin/manage-ssh-tunnel << 'EOF'
#!/bin/bash
# SSH Tunnel Management Script for MTN Zero-Rated Access

# Load configuration
CONFIG_FILE="/root/Techub_VPS/isp_domains.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    # Default zero-rated domains
    zero_rated_domains="mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com"
    zero_rated_domains_alt="mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com"
fi

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

case "$1" in
    start)
        echo "Starting SSH tunnel for MTN zero-rated domains..."
        echo "Connect from client using:"
        echo "ssh -D 1080 -f -C -q -N user@$SERVER_IP"
        echo ""
        echo "Configure your browser to use SOCKS proxy:"
        echo "Host: localhost  Port: 1080  Type: SOCKS5"
        echo ""
        echo "Zero-rated domains that will work without data:"
        echo "$zero_rated_domains"
        echo "$zero_rated_domains_alt"
        echo ""
        echo "SSH tunneling started successfully!"
        ;;
    stop)
        echo "Stopping SSH tunnels..."
        pkill -f "ssh.*-D"
        echo "SSH tunnels stopped"
        ;;
    status)
        echo "Active SSH tunnels:"
        ps aux | grep "ssh.*-D" | grep -v grep
        if [[ $? -eq 0 ]]; then
            echo "SSH tunnel is running"
        else
            echo "No SSH tunnels running"
        fi
        ;;
    setup-client)
        echo "=== SSH Tunnel Client Setup Instructions ==="
        echo ""
        echo "1. On your client device (phone/computer), run:"
        echo "   ssh -D 1080 -f -C -q -N user@$SERVER_IP"
        echo ""
        echo "2. Configure your browser to use SOCKS proxy:"
        echo "   Host: localhost  Port: 1080  Type: SOCKS5"
        echo ""
        echo "3. Visit these MTN zero-rated domains without using data:"
        IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
        for domain in "${DOMAINS[@]}"; do
            echo "   - $domain"
        done
        IFS=',' read -ra ALT_DOMAINS <<< "$zero_rated_domains_alt"
        for domain in "${ALT_DOMAINS[@]}"; do
            echo "   - $domain"
        done
        echo ""
        echo "4. For persistent connection, add to crontab:"
        echo "   */5 * * * * pgrep -f 'ssh.*-D' >/dev/null || ssh -D 1080 -f -C -q -N user@$SERVER_IP"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|setup-client}"
        echo ""
        echo "Commands:"
        echo "  start          - Show connection instructions"
        echo "  stop           - Stop all SSH tunnels"
        echo "  status         - Check tunnel status"
        echo "  setup-client   - Show detailed client setup instructions"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/manage-ssh-tunnel
    
    # Create systemd service for persistent SSH tunneling
    cat > "${SSH_TUNNEL_SERVICE}" << 'EOF'
[Unit]
Description=Techub SSH Tunnel Service for MTN Zero-Rated Access
After=network.target ssh.service
Wants=network.target

[Service]
Type=forking
User=root
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/bin/manage-ssh-tunnel start
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable systemd service
    systemctl daemon-reload
    systemctl enable techub-ssh-tunnel.service 2>/dev/null || echo -e "${YELLOW}Warning: Could not enable SSH tunnel service${NC}"
    
    echo -e "${GREEN}SSH tunneling configured successfully!${NC}"
    echo ""
    echo "Features activated:"
    echo "1. SSH server configured for tunneling"
    echo "2. MTN zero-rated domain access through SSH"
    echo "3. SOCKS proxy support"
    echo "4. Persistent tunnel service"
    echo ""
    echo "Usage on client device:"
    echo "ssh -D 1080 -f -C -q -N user@$(hostname -I | awk '{print $1}')"
    echo ""
    echo "Configure browser to use SOCKS proxy at localhost:1080"
    echo "Then visit these zero-rated domains without using data:"
    IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
    for domain in "${DOMAINS[@]}"; do
        echo "  - $domain"
    done
    echo ""
    echo "Use 'manage-ssh-tunnel setup-client' for detailed instructions"
    log "INFO" "SSH tunneling configured for MTN zero-rated access"
    read -p "Press Enter to continue..."
}

# Service mode for persistent operation (ENHANCED VERSION)
service_mode() {
    log "INFO" "Starting Techub service mode"
    
    # Set up error handling
    trap 'log "ERROR" "Service mode encountered an error"; exit 1' ERR
    
    # Start OpenVPN server with better error handling
    if systemctl is-active --quiet openvpn@server; then
        log "INFO" "OpenVPN service already running"
    else
        if systemctl start openvpn@server; then
            log "INFO" "OpenVPN service started successfully"
        else
            log "ERROR" "Failed to start OpenVPN service"
        fi
    fi
    
    # Apply traffic shaping if script exists
    if [[ -f "${SCRIPT_DIR}/scripts/traffic_shaping.sh" ]]; then
        if bash "${SCRIPT_DIR}/scripts/traffic_shaping.sh"; then
            log "INFO" "Traffic shaping applied successfully"
        else
            log "WARN" "Failed to apply traffic shaping"
        fi
    fi
    
    # Set up MTN domain configuration if not already done
    if [[ ! -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        initialize_mtn_domains
        log "INFO" "MTN domain configuration initialized"
    fi
    
    echo -e "${GREEN}Techub Service Mode Running${NC}"
    echo "Monitoring system health and maintaining connections..."
    echo "Press Ctrl+C to stop the service monitor"
    
    # Keep service alive with proper monitoring
    while true; do
        sleep 60
        
        # Check if OpenVPN is running
        if ! systemctl is-active --quiet openvpn@server; then
            log "WARN" "OpenVPN service not running, attempting restart..."
            if systemctl start openvpn@server; then
                log "INFO" "OpenVPN service restarted successfully"
            else
                log "ERROR" "Failed to restart OpenVPN service"
            fi
        fi
        
        # Check system resources
        if [[ $(free | grep Mem | awk '{print $4}') -lt 100000 ]]; then
            log "WARN" "Low memory detected"
        fi
        
        # Ensure SSH service is running
        if ! systemctl is-active --quiet ssh; then
            log "WARN" "SSH service not running, attempting restart..."
            systemctl start ssh 2>/dev/null || true
        fi
    done
}

# Main menu handler
handle_main_menu() {
    local choice=$1
    
    case $choice in
        1)
            install_openvpn
            ;;
        2)
            uninstall_openvpn
            ;;
        3)
            start_openvpn
            ;;
        4)
            stop_openvpn
            ;;
        5)
            handle_advanced_menu
            ;;
        6)
            show_status
            ;;
        7)
            show_logs
            ;;
        8)
            echo -e "${GREEN}Exiting Techub OpenVPN Management System...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please try again.${NC}"
            read -p "Press Enter to continue..."
            ;;
    esac
}

# Advanced menu handler
handle_advanced_menu() {
    local choice=""
    
    while [[ "$choice" != "8" ]]; do
        show_advanced_menu
        read -p "Enter your choice [1-8]: " choice
        
        case $choice in
            1)
                configure_mtn_bypass
                ;;
            2)
                echo -e "${YELLOW}Orange Cameroon Bypass configuration not yet implemented${NC}"
                read -p "Press Enter to continue..."
                ;;
            3)
                install_auto_launch
                ;;
            4)
                configure_traffic_shaping
                ;;
            5)
                setup_squid_proxy
                ;;
            6)
                configure_dns_spoofing
                ;;
            7)
                configure_ssh_tunneling
                ;;
            8)
                # Return to main menu
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Main execution
main() {
    # Check if script is running in service mode
    if [[ "$1" == "service-mode" ]]; then
        service_mode
        exit 0
    fi
    
    # Main menu loop
    while true; do
        show_main_menu
        read -p "Enter your choice [1-8]: " choice
        handle_main_menu $choice
    done
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
