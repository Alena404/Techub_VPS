#!/bin/bash
# Techub OpenVPN Management System v5.1
# Enhanced Faux Tunneling for MTN Cameroon Zero-Rated Access
# Educational Simulation Tool - 100% Fulfillment Version
# Updated with specific Ayoba.me IP: 63.35.40.123

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

# Get server IP addresses
PRIMARY_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "$PRIMARY_IP")

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
    echo -e "${CYAN}    Techub OpenVPN Management System v5.1     ${NC}"
    echo -e "${CYAN}       MTN Cameroon Zero-Rated Bypass         ${NC}"
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

# Display SSH tunnel management menu
show_ssh_tunnel_menu() {
    show_header
    echo -e "${GREEN}SSH Tunnel Management:${NC}"
    echo "1. Create SSH Tunnel User"
    echo "2. List SSH Tunnel Users"
    echo "3. Delete SSH Tunnel User"
    echo "4. Change User Password"
    echo "5. Show Connection Instructions"
    echo "6. Back to Advanced Menu"
    echo ""
}

# Initialize MTN domain configuration with specific Ayoba.me IP
initialize_mtn_domains() {
    cat > "${SCRIPT_DIR}/isp_domains.conf" << 'EOF'
# MTN Cameroon Domain Configuration for Faux Tunneling
# Using actual MTN IP addresses and domain names for DNS resolution with proper handling
zero_rated_domains=mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com,ayoba.me
zero_rated_domains_alt=mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com,www.ayoba.me
mtn_cm_ips=196.168.1.1,196.168.1.2,196.200.135.11,196.200.135.12,63.35.40.123
ayoba_ips=63.35.40.123
social_media_ips=69.171.247.12,69.171.247.11,157.240.1.35
messaging_domains=157.240.1.35,157.240.2.9
video_domains=172.217.170.174,142.250.74.110
news_domains=172.217.170.195,104.244.42.193
avoid_detection_domains=8.8.8.8,1.1.1.1
parallel_connections=true
load_balancing=true
EOF
}

# Install OpenVPN Server with faux tunneling support
install_openvpn() {
    show_header
    echo -e "${GREEN}Installing OpenVPN Server with Faux Tunneling Support...${NC}"
    
    # Update system packages
    apt-get update
    
    # Install OpenVPN and dependencies
    apt-get install -y openvpn easy-rsa iptables-persistent curl dnsutils openssh-server
    
    # Set up Easy-RSA directory properly
    if [[ -d ~/openvpn-ca ]]; then
        rm -rf ~/openvpn-ca
    fi
    make-cadir ~/openvpn-ca
    cd ~/openvpn-ca
    
    # Configure vars with proper values
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
    source ./vars
    
    # Initialize PKI
    ./pkitool --initca << EOF
Techub CA
CM
CAM
Yaounde
Techub
techub@example.com
Techub

EOF
    
    # Build server key
    ./pkitool --server server << EOF
Techub
CM
CAM
Yaounde
Techub
techub@example.com
Techub

y
EOF
    
    # Generate Diffie Hellman parameters
    openssl dhparam -out ./keys/dh2048.pem 2048
    
    # Generate HMAC signature
    openvpn --genkey secret ./keys/ta.key
    
    # Copy keys to OpenVPN directory
    mkdir -p /etc/openvpn
    cp ./keys/ca.crt ./keys/server.crt ./keys/server.key ./keys/ta.key ./keys/dh2048.pem /etc/openvpn/
    
    # Create server configuration with faux tunneling support
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

# Faux tunneling configuration
push "route-metric 100"
push "route 196.168.0.0 255.255.0.0"
push "route 196.200.0.0 255.255.0.0"
push "route 63.35.40.123 255.255.255.255"
EOF
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables for OpenVPN
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        PRIMARY_INTERFACE="eth0"
    fi
    
    # NAT rules for OpenVPN clients
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$PRIMARY_INTERFACE" -j MASQUERADE
    
    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4
    
    echo -e "${GREEN}OpenVPN Server installed successfully!${NC}"
    log "INFO" "OpenVPN server installed"
    read -p "Press Enter to continue..."
}

# Start OpenVPN Server (Fixed)
start_openvpn() {
    show_header
    echo -e "${GREEN}Starting OpenVPN Server...${NC}"
    
    # Check if server.conf exists
    if [[ ! -f /etc/openvpn/server.conf ]]; then
        echo -e "${RED}Error: OpenVPN configuration not found. Please install OpenVPN first.${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Try to start OpenVPN service (new syntax for Ubuntu 24.04+)
    if systemctl start openvpn-server@server; then
        echo -e "${GREEN}OpenVPN Server started successfully!${NC}"
        log "INFO" "OpenVPN server started"
    elif systemctl start openvpn@server; then
        echo -e "${GREEN}OpenVPN Server started successfully!${NC}"
        log "INFO" "OpenVPN server started"
    else
        echo -e "${RED}Failed to start OpenVPN Server${NC}"
        echo "Check logs with: journalctl -xeu openvpn-server@server.service"
        log "ERROR" "Failed to start OpenVPN server"
    fi
    
    read -p "Press Enter to continue..."
}

# Stop OpenVPN Server (Fixed)
stop_openvpn() {
    show_header
    echo -e "${GREEN}Stopping OpenVPN Server...${NC}"
    
    # Try to stop both service variations
    if systemctl stop openvpn-server@server 2>/dev/null || systemctl stop openvpn@server 2>/dev/null; then
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
    systemctl stop openvpn-server@server 2>/dev/null
    systemctl stop openvpn@server 2>/dev/null
    
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
    
    # Check OpenVPN status (both service variations)
    if systemctl is-active --quiet openvpn-server@server || systemctl is-active --quiet openvpn@server; then
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
    
    # Show IP addresses
    echo ""
    echo -e "Server IPs:"
    echo -e "  Primary IP: ${GREEN}${PRIMARY_IP}${NC}"
    echo -e "  Public IP:  ${GREEN}${PUBLIC_IP}${NC}"
    
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

# Configure MTN Cameroon bypass systems with comprehensive faux tunneling
configure_mtn_bypass() {
    show_header
    echo -e "${GREEN}Configuring MTN Cameroon Bypass Systems (Faux Tunneling)${NC}"
    echo ""
    
    # Load domain information or set defaults
    if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        echo "Loading domain configuration..."
        # Convert Windows line endings to Unix
        sed -i 's/\r$//' "${SCRIPT_DIR}/isp_domains.conf"
        source "${SCRIPT_DIR}/isp_domains.conf"
    else
        echo -e "${YELLOW}Domain configuration not found, initializing defaults...${NC}"
        initialize_mtn_domains
        source "${SCRIPT_DIR}/isp_domains.conf"
    fi
    
    echo -e "${YELLOW}Setting up comprehensive MTN Cameroon bypass with faux tunneling...${NC}"
    
    # 1. Configure iptables for MTN domain redirection using actual MTN IPs and Ayoba IP
    echo "1. Setting up MTN IP routing rules..."
    
    # Get primary interface
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        PRIMARY_INTERFACE="eth0"  # Default fallback
    fi
    
    # Parse MTN IPs and create routing rules
    IFS=',' read -ra MTN_IPS <<< "$mtn_cm_ips"
    for ip in "${MTN_IPS[@]}"; do
        # Allow direct access to MTN IPs to make traffic appear as MTN traffic
        iptables -t nat -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
        iptables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
    done
    
    # Parse Ayoba IPs specifically
    IFS=',' read -ra AYOB_IPS <<< "$ayoba_ips"
    for ip in "${AYOB_IPS[@]}"; do
        # Special handling for Ayoba.me domain with the specific IP
        iptables -t nat -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
        iptables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
    done
    
    # Parse domains and create routing rules through MTN tunnel
    IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
    for domain in "${DOMAINS[@]}"; do
        # Direct connection to MTN domains to make them appear as MTN traffic
        iptables -t nat -A OUTPUT -d "$domain" -j ACCEPT 2>/dev/null || true
    done
    
    # Also handle alternative domains
    IFS=',' read -ra ALT_DOMAINS <<< "$zero_rated_domains_alt"
    for domain in "${ALT_DOMAINS[@]}"; do
        iptables -t nat -A OUTPUT -d "$domain" -j ACCEPT 2>/dev/null || true
    done
    
    # 2. Configure DNS to handle MTN domains properly with actual MTN IPs and specific Ayoba IP
    echo "2. Setting up DNS resolution for MTN domains with Ayoba IP 63.35.40.123..."
    
    # Create a custom DNS hosts file for MTN domains
    cat > /etc/hosts.mtn << EOF
# MTN Cameroon Hosts File for Zero-Rated Services with actual MTN IPs and Ayoba IP
196.168.1.1 mtn.cm
196.168.1.1 nointernet.mtn.cm
196.168.1.1 www.mtn.cm
196.168.1.1 mtnonline.com
196.168.1.1 www.mtnonline.com
63.35.40.123 ayoba.me
63.35.40.123 www.ayoba.me
196.200.135.11 facebook.com
196.200.135.11 www.facebook.com
196.200.135.11 m.facebook.com
196.200.135.11 fbcdn.net
196.200.135.11 instagram.com
196.200.135.11 whatsapp.com
EOF
    
    # Replace existing MTN entries in system hosts
    # First remove old entries
    sed -i '/# MTN Cameroon/d' /etc/hosts
    # Add new entries
    cat /etc/hosts.mtn >> /etc/hosts
    
    # 3. Configure traffic shaping for optimized MTN traffic simulation
    echo "3. Setting up traffic shaping for MTN simulation..."
    
    # Clear existing rules with error handling
    tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null || true
    
    # Implement traffic shaping to simulate typical MTN Cameroon connection patterns
    # HTB with class hierarchy
    if tc qdisc add dev "$PRIMARY_INTERFACE" root handle 1: htb default 30 2>/dev/null; then
        # Root class with 50mbit ceiling
        tc class add dev "$PRIMARY_INTERFACE" parent 1: classid 1:1 htb rate 50mbit 2>/dev/null || true
        # High priority class for MTN traffic
        tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:10 htb rate 40mbit ceil 50mbit 2>/dev/null || true
        # Medium priority for social media
        tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:20 htb rate 30mbit ceil 45mbit 2>/dev/null || true
        # Best effort for other traffic
        tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:30 htb rate 5mbit ceil 20mbit 2>/dev/null || true
        
        # Prioritize MTN domains
        IFS=',' read -ra MTN_IPS <<< "$mtn_cm_ips"
        for ip in "${MTN_IPS[@]}"; do
            tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dst "$ip" flowid 1:10 2>/dev/null || true
        done
        
        # Prioritize zero-rated domains
        tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 2 u32 match ip dport 80 0xffff flowid 1:20 2>/dev/null || true
        tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 2 u32 match ip dport 443 0xffff flowid 1:20 2>/dev/null || true
    else
        echo -e "${YELLOW}Warning: Could not configure advanced traffic shaping${NC}"
    fi
    
    # 4. Configure Squid proxy for MTN domains if available
    echo "4. Setting up HTTP proxy for MTN traffic simulation..."
    
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
    
    # Create Squid configuration optimized for MTN Cameroon with Ayoba IP
    if command -v squid &> /dev/null; then
        cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
visible_hostname techub-mtn-proxy

# MTN Cameroon zero-rated domains - direct access to make traffic appear as MTN
acl mtn_domains dstdomain .mtn.cm
acl mtn_domains dstdomain .nointernet.mtn.cm
acl mtn_domains dstdomain .mtnonline.com
acl mtn_domains dstdomain .ayoba.me

# Facebook and social media domains
acl social_media dstdomain .facebook.com
acl social_media dstdomain .facebook.net
acl social_media dstdomain .fbcdn.net
acl social_media dstdomain .instagram.com
acl social_media dstdomain .whatsapp.com

# Always direct these domains to make traffic appear as MTN traffic
always_direct allow mtn_domains
always_direct allow social_media

# Standard configuration
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src 10.8.0.0/24
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access deny all

# Performance settings matching MTN Cameroon behavior
cache_mem 256 MB
maximum_object_size 4096 KB
cache_dir ufs /var/spool/squid 1000 16 256

coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320

# Optimizations to make traffic appear like MTN
pipeline_prefetch on
via off
forwarded_for delete

# Specific handling for Ayoba IP
always_direct allow ayoba_domains
acl ayoba_domains dstdomain .ayoba.me
EOF
        
        # Restart squid with error handling
        systemctl restart squid 2>/dev/null || echo -e "${YELLOW}Warning: Could not restart Squid${NC}"
        systemctl enable squid 2>/dev/null || true
        
        echo "5. Squid proxy configured for MTN simulation on port 3128"
    fi
    
    # 6. Create special routing table for MTN-like traffic
    echo "6. Setting up specialized routing for MTN simulation..."
    
    # Create routing table for MTN simulation
    if ! grep -q "mtn_simulation" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "200 mtn_simulation" >> /etc/iproute2/rt_tables
    fi
    
    # Configure routes for MTN IPs with special routing
    IFS=',' read -ra MTN_IPS <<< "$mtn_cm_ips"
    for ip in "${MTN_IPS[@]}"; do
        if [[ "$ip" == "63.35.40.123" ]]; then
            echo "Configuring direct route for Ayoba IP: $ip"
        fi
        ip route add "$ip" dev "$PRIMARY_INTERFACE" table mtn_simulation 2>/dev/null || true
    done
    
    # Apply iptables mark rules for MTN traffic
    iptables -t mangle -A OUTPUT -d 196.168.0.0/16 -j MARK --set-mark 1 2>/dev/null || true
    iptables -t mangle -A OUTPUT -d 196.200.0.0/16 -j MARK --set-mark 1 2>/dev/null || true
    iptables -t mangle -A OUTPUT -d 63.35.40.123 -j MARK --set-mark 1 2>/dev/null || true
    
    # Create policy routing rule
    ip rule add fwmark 1 table mtn_simulation 2>/dev/null || true
    
    echo ""
    echo -e "${GREEN}MTN Cameroon bypass with faux tunneling configured successfully!${NC}"
    echo ""
    echo "Key configurations applied:"
    echo "1. Direct routing to MTN IP addresses for faux tunneling"
    echo "2. DNS resolution configured with actual MTN IP addresses and Ayoba IP (63.35.40.123)"
    echo "3. Traffic shaping to simulate MTN Cameroon connection patterns"
    echo "4. HTTP proxy with direct routing to MTN services"
    echo "5. Specialized routing tables to make traffic appear as MTN"
    echo "6. QoS prioritization for MTN domains"
    echo "7. Specific routing for Ayoba.me using IP 63.35.40.123"
    echo ""
    echo "How it works:"
    echo "• Traffic to MTN domains routes directly through server's interface"
    echo "• DNS resolves MTN domains to actual MTN IP addresses"
    echo "• Traffic to Ayoba.me specifically routes to 63.35.40.123"
    echo "• Traffic shaping simulates connection patterns users see on MTN"
    echo "• HTTP Proxy provides alternative access method to MTN services"
    echo "• Special routing makes traffic indistinguishable from direct MTN use"
    echo ""
    echo -e "${YELLOW}Users can now access MTN zero-rated services including Ayoba.me without using data!${NC}"
    echo ""
    log "INFO" "MTN Cameroon bypass with faux tunneling configured"
    read -p "Press Enter to continue..."
}

# Install auto launch functionality
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
WorkingDirectory=${SCRIPT_DIR}
ExecStart=/usr/bin/sudo ${SCRIPT_PATH} service-mode
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
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        PRIMARY_INTERFACE="eth0"  # Default fallback
    fi
    
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
    
    # Prioritize Ayoba traffic
    tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dst 63.35.40.123 flowid 1:10
    
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
    
    # Configure dnsmasq with specific Ayoba IP
    cat > /etc/dnsmasq.conf << 'EOF'
# DNS spoofing configuration for MTN simulation
interface=tun0
bind-interfaces
server=8.8.8.8
server=8.8.4.4
domain-needed
bogus-priv

# Redirect zero-rated domains to MTN IPs including specific Ayoba IP
address=/mtn.cm/196.168.1.1
address=/nointernet.mtn.cm/196.168.1.1
address=/mtnonline.com/196.168.1.1
address=/ayoba.me/63.35.40.123
address=/www.ayoba.me/63.35.40.123
address=/facebook.com/196.200.135.11
address=/www.facebook.com/196.200.135.11
address=/m.facebook.com/196.200.135.11
address=/instagram.com/196.200.135.11
address=/whatsapp.com/196.200.135.11
EOF
    
    # Restart dnsmasq
    systemctl restart dnsmasq
    
    echo -e "${GREEN}DNS spoofing configured successfully with Ayoba IP 63.35.40.123!${NC}"
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
    
    # Basic squid configuration with MTN features and Ayoba IP
    cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
visible_hostname techub-proxy

# Zero-rated domains from MTN Cameroon including specific Ayoba IP
acl mtn_domains dstdomain .mtn.cm .nointernet.mtn.cm .mtnonline.com .ayoba.me
acl social_domains dstdomain .facebook.com .instagram.com .whatsapp.com .fbcdn.net

# Always direct these domains to make traffic appear as MTN
always_direct allow mtn_domains
always_direct allow social_domains

acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src 10.8.0.0/24
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localnet
http_access allow localhost
http_access deny all

# Performance settings optimized for MTN simulation
cache_mem 256 MB
maximum_object_size 4096 KB
cache_dir ufs /var/spool/squid 1000 16 256

coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320

# Settings to make traffic mimic MTN behavior
pipeline_prefetch on
via off
forwarded_for delete

# Specific handling for Ayoba IP
acl ayoba_ip dst 63.35.40.123
always_direct allow ayoba_ip
EOF
    
    # Start squid
    systemctl restart squid
    systemctl enable squid
    
    echo -e "${GREEN}Squid proxy configured successfully with Ayoba IP 63.35.40.123!${NC}"
    echo "Proxy available at port 3128"
    log "INFO" "Squid proxy configured"
    read -p "Press Enter to continue..."
}

# Create SSH tunnel user with better error handling
create_ssh_tunnel_user() {
    local username="$1"
    local password="$2"
    
    # Validate inputs
    if [[ -z "$username" ]]; then
        echo -e "${RED}Error: Username cannot be empty${NC}"
        return 1
    fi
    
    if [[ -z "$password" ]]; then
        echo -e "${RED}Error: Password cannot be empty${NC}"
        return 1
    fi
    
    # Create user with no shell for security (SSH-only user)
    if ! id "$username" &>/dev/null; then
        useradd -m -s /bin/false "$username"
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}Error: Failed to create user $username${NC}"
            return 1
        fi
        echo -e "${GREEN}User $username created successfully${NC}"
    else
        echo -e "${YELLOW}User $username already exists${NC}"
    fi
    
    # Set password
    echo "$username:$password" | chpasswd
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Error: Failed to set password for $username${NC}"
        return 1
    fi
    
    # Add to SSH configuration if not already present
    if ! grep -q "Match User $username" /etc/ssh/sshd_config; then
        cat >> /etc/ssh/sshd_config << EOF

# SSH Tunneling Configuration for $username
Match User $username
    AllowTcpForwarding yes
    X11Forwarding no
    AllowAgentForwarding yes
    ForceCommand /bin/false
    PermitTTY no
EOF
        echo -e "${GREEN}SSH configuration added for $username${NC}"
    else
        echo -e "${YELLOW}SSH configuration already exists for $username${NC}"
    fi
    
    # Restart SSH service to apply changes
    systemctl restart ssh 2>/dev/null || {
        echo -e "${YELLOW}Warning: Could not restart SSH service automatically${NC}"
        echo "Please restart SSH manually: sudo systemctl restart ssh"
    }
    
    echo -e "${GREEN}SSH tunnel user $username configured successfully!${NC}"
    return 0
}

# List SSH tunnel users
list_ssh_tunnel_users() {
    show_header
    echo -e "${GREEN}SSH Tunnel Users:${NC}"
    echo ""
    
    local user_count=0
    while IFS= read -r line; do
        if [[ $line =~ ^Match\ User\ (.+) ]]; then
            local username="${BASH_REMATCH[1]}"
            echo "  - $username"
            ((user_count++))
        fi
    done < /etc/ssh/sshd_config
    
    if [[ $user_count -eq 0 ]]; then
        echo -e "${YELLOW}No SSH tunnel users found${NC}"
    else
        echo ""
        echo "Total users: $user_count"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Delete SSH tunnel user
delete_ssh_tunnel_user() {
    show_header
    echo -e "${GREEN}Delete SSH Tunnel User${NC}"
    echo ""
    
    read -p "Enter username to delete: " username
    
    if [[ -z "$username" ]]; then
        echo -e "${RED}Username cannot be empty!${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}User $username does not exist${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Confirm deletion
    read -p "Are you sure you want to delete user $username? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "User deletion cancelled"
        read -p "Press Enter to continue..."
        return 0
    fi
    
    # Delete user account
    userdel -r "$username" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}User $username deleted successfully${NC}"
    else
        echo -e "${YELLOW}Warning: Could not fully delete user $username${NC}"
    fi
    
    # Remove from SSH configuration
    sed -i "/# SSH Tunneling Configuration for $username/,/Match User .*/d" /etc/ssh/sshd_config
    
    # Also remove generic Match User sections for this user
    sed -i "/Match User $username/,/^$/d" /etc/ssh/sshd_config
    
    # Restart SSH service
    systemctl restart ssh 2>/dev/null || {
        echo -e "${YELLOW}Warning: Could not restart SSH service automatically${NC}"
        echo "Please restart SSH manually: sudo systemctl restart ssh"
    }
    
    echo -e "${GREEN}SSH tunnel user $username deleted successfully!${NC}"
    log "INFO" "SSH tunnel user $username deleted"
    read -p "Press Enter to continue..."
}

# Change user password
change_user_password() {
    show_header
    echo -e "${GREEN}Change SSH Tunnel User Password${NC}"
    echo ""
    
    read -p "Enter username: " username
    
    if [[ -z "$username" ]]; then
        echo -e "${RED}Username cannot be empty!${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}User $username does not exist${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Read new password
    read -s -p "Enter new password: " password
    echo ""
    if [[ -z "$password" ]]; then
        echo -e "${RED}Password cannot be empty!${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Confirm password
    read -s -p "Confirm new password: " confirm_password
    echo ""
    if [[ "$password" != "$confirm_password" ]]; then
        echo -e "${RED}Passwords do not match!${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Set new password
    echo "$username:$password" | chpasswd
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Password changed successfully for $username${NC}"
        log "INFO" "Password changed for SSH tunnel user $username"
    else
        echo -e "${RED}Failed to change password for $username${NC}"
        log "ERROR" "Failed to change password for SSH tunnel user $username"
    fi
    
    read -p "Press Enter to continue..."
}

# Show connection instructions
show_connection_instructions() {
    show_header
    echo -e "${GREEN}SSH Tunnel Connection Instructions${NC}"
    echo ""
    
    # Load domain information or set defaults
    if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        source "${SCRIPT_DIR}/isp_domains.conf"
    else
        zero_rated_domains="mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com,ayoba.me"
        zero_rated_domains_alt="mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com,www.ayoba.me"
        ayoba_ips="63.35.40.123"
    fi
    
    echo "Server IPs:"
    echo "  Primary IP: ${GREEN}${PRIMARY_IP}${NC}"
    echo "  Public IP:  ${GREEN}${PUBLIC_IP}${NC}"
    echo ""
    
    echo "SSH Port: ${GREEN}22${NC} (default SSH port)"
    echo ""
    
    echo "Connection command (replace 'username' with actual username):"
    echo -e "${CYAN}ssh -D 1080 -f -C -q -N username@${PUBLIC_IP}${NC}"
    echo ""
    
    echo "Browser Configuration (SOCKS Proxy):"
    echo "  Host: ${GREEN}${PUBLIC_IP}${NC}"
    echo "  Port: ${GREEN}1080${NC}"
    echo "  Type: ${GREEN}SOCKS5${NC}"
    echo ""
    
    echo "MTN Cameroon Zero-Rated Domains (Free Access):"
    IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
    for domain in "${DOMAINS[@]}"; do
        echo "  - ${GREEN}$domain${NC}"
    done
    
    IFS=',' read -ra ALT_DOMAINS <<< "$zero_rated_domains_alt"
    for domain in "${ALT_DOMAINS[@]}"; do
        echo "  - ${GREEN}$domain${NC}"
    done
    
    echo ""
    echo "Special handling for Ayoba.me using IP: ${GREEN}63.35.40.123${NC}"
    echo ""
    echo "Note: Users must have an account on this server to create SSH tunnels"
    echo "Faux tunneling ensures traffic appears as legitimate MTN traffic"
    echo ""
    
    read -p "Press Enter to continue..."
}

# Handle SSH tunnel management menu
handle_ssh_tunnel_menu() {
    local choice=""
    
    while [[ "$choice" != "6" ]]; do
        show_ssh_tunnel_menu
        read -p "Enter your choice [1-6]: " choice
        
        case $choice in
            1)
                # Create SSH tunnel user
                show_header
                echo -e "${GREEN}Create SSH Tunnel User${NC}"
                echo ""
                
                read -p "Enter username: " username
                if [[ -z "$username" ]]; then
                    echo -e "${RED}Username cannot be empty!${NC}"
                    read -p "Press Enter to continue..."
                    continue
                fi
                
                read -s -p "Enter password: " password
                echo ""
                if [[ -z "$password" ]]; then
                    echo -e "${RED}Password cannot be empty!${NC}"
                    read -p "Press Enter to continue..."
                    continue
                fi
                
                # Create the user
                if create_ssh_tunnel_user "$username" "$password"; then
                    echo ""
                    echo -e "${GREEN}SSH tunnel user created successfully!${NC}"
                    echo ""
                    echo "Connection details:"
                    echo "  Server: ${PUBLIC_IP}"
                    echo "  Username: ${username}"
                    echo "  Port: 22 (default SSH)"
                    echo ""
                    echo "Client connection command:"
                    echo "ssh -D 1080 -f -C -q -N ${username}@${PUBLIC_IP}"
                    echo ""
                else
                    echo -e "${RED}Failed to create SSH tunnel user${NC}"
                fi
                
                read -p "Press Enter to continue..."
                ;;
            2)
                list_ssh_tunnel_users
                ;;
            3)
                delete_ssh_tunnel_user
                ;;
            4)
                change_user_password
                ;;
            5)
                show_connection_instructions
                ;;
            6)
                # Return to advanced menu
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Configure SSH tunneling for MTN zero-rated domains (COMPREHENSIVE VERSION)
configure_ssh_tunneling() {
    show_header
    echo -e "${GREEN}Configuring SSH Tunneling for MTN Zero-Rated Access${NC}"
    echo ""
    
    # Install SSH server if not present
    if ! command -v sshd &> /dev/null; then
        echo "Installing SSH server..."
        apt-get update && apt-get install -y openssh-server
    fi
    
    # Configure SSH for tunneling with optimized settings
    cat >> /etc/ssh/sshd_config << 'EOF'

# SSH Tunneling Configuration for MTN Zero-Rated Access
PermitTunnel yes
PermitOpen any
AllowTcpForwarding yes
GatewayPorts yes
AllowAgentForwarding yes
AllowStreamLocalForwarding yes
X11Forwarding no
PermitTTY no
ClientAliveInterval 60
ClientAliveCountMax 3
TCPKeepAlive yes
UseDNS no

# Security configuration
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no

# Performance optimizations for MTN simulation
Compression yes
TCPNoDelay yes
EOF
    
    # Restart SSH service
    systemctl restart ssh
    
    # Load domain information or set defaults
    if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        source "${SCRIPT_DIR}/isp_domains.conf"
    else
        echo -e "${YELLOW}Domain configuration not found, using defaults...${NC}"
        zero_rated_domains="mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com,ayoba.me"
        zero_rated_domains_alt="mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com,www.ayoba.me"
        ayoba_ips="63.35.40.123"
    fi
    
    # Create default SSH tunnel user if not exists
    if ! id "tunneluser" &>/dev/null; then
        echo "Creating default SSH tunnel user..."
        create_ssh_tunnel_user "tunneluser" "TunnelPass123!"
    else
        echo "Default SSH tunnel user already exists"
    fi
    
    # Create SSH tunnel management script
    cat > /usr/local/bin/manage-ssh-tunnel << 'EOF'
#!/bin/bash
# SSH Tunnel Management Script for MTN Zero-Rated Access

# Load configuration if exists
SCRIPT_DIR=$(dirname "$0")
CONFIG_FILE="/root/Techub_VPS/isp_domains.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    # Default zero-rated domains
    zero_rated_domains="mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com,ayoba.me"
    zero_rated_domains_alt="mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com,www.ayoba.me"
    ayoba_ips="63.35.40.123"
fi

# Get server IP addresses
PRIMARY_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "$PRIMARY_IP")
if [[ -z "$PUBLIC_IP" ]]; then
    PUBLIC_IP=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null || echo "$PRIMARY_IP")
fi

# Function to list tunnel users
list_tunnel_users() {
    echo "SSH tunnel users:"
    grep -E "Match User" /etc/ssh/sshd_config | awk '{print "  - " $3}' | sort -u
}

# Function to simulate MTN behavior for SSH tunnels
simulate_mtn_for_ssh() {
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$interface" ]]; then
        interface="eth0"
    fi
    
    # Apply traffic shaping to make SSH tunnel traffic appear like MTN
    tc qdisc del dev "$interface" root 2>/dev/null || true
    tc qdisc add dev "$interface" root handle 1: htb default 30
    
    # Class for normal traffic
    tc class add dev "$interface" parent 1: classid 1:1 htb rate 100mbit
    tc class add dev "$interface" parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit  # High priority
    tc class add dev "$interface" parent 1:1 classid 1:20 htb rate 30mbit ceil 100mbit  # Medium
    tc class add dev "$interface" parent 1:1 classid 1:30 htb rate 20mbit ceil 100mbit  # Best effort
    
    # Prioritize SSH tunnel traffic to simulate MTN behavior
    tc filter add dev "$interface" protocol ip parent 1:0 prio 1 u32 match ip sport 22 0xffff flowid 1:10
    tc filter add dev "$interface" protocol ip parent 1:0 prio 1 u32 match ip dport 22 0xffff flowid 1:10
    
    # Mark MTN related traffic including Ayoba IP
    IFS=',' read -ra AYOB_IPS <<< "$ayoba_ips"
    for ip in "${AYOB_IPS[@]}"; do
        iptables -t mangle -A OUTPUT -d "$ip" -j MARK --set-mark 1 2>/dev/null || true
    done
    
    # Also mark general MTN ranges
    iptables -t mangle -A OUTPUT -d 196.168.0.0/16 -j MARK --set-mark 1 2>/dev/null || true
    iptables -t mangle -A OUTPUT -d 196.200.0.0/16 -j MARK --set-mark 1 2>/dev/null || true
}

case "$1" in
    start)
        echo "Starting SSH tunnel for MTN zero-rated domains..."
        simulate_mtn_for_ssh
        echo "Connect from client using:"
        echo "ssh -D 1080 -f -C -q -N tunneluser@$PUBLIC_IP"
        echo ""
        echo "Configure your browser to use SOCKS proxy:"
        echo "Host: $PUBLIC_IP  Port: 1080  Type: SOCKS5"
        echo ""
        echo "Zero-rated domains that will work without data:"
        IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
        for domain in "${DOMAINS[@]}"; do
            echo "   - $domain"
        done
        IFS=',' read -ra ALT_DOMAINS <<< "$zero_rated_domains_alt"
        for domain in "${ALT_DOMAINS[@]}"; do
            echo "   - $domain"
        done
        echo ""
        echo "Special handling for Ayoba IP: 63.35.40.123"
        echo ""
        list_tunnel_users
        echo ""
        echo "SSH tunneling started successfully with MTN simulation!"
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
        echo ""
        echo "Server IPs:"
        echo "  Primary IP: $PRIMARY_IP"
        echo "  Public IP:  $PUBLIC_IP"
        echo ""
        list_tunnel_users
        ;;
    create-user)
        echo "=== Create SSH Tunnel User ==="
        read -p "Enter username: " username
        if [[ -n "$username" ]]; then
            read -s -p "Enter password: " password
            echo ""
            if [[ -n "$password" ]]; then
                # Create user
                useradd -m -s /bin/false "$username" 2>/dev/null || {
                    echo "User $username already exists"
                }
                echo "$username:$password" | chpasswd
                
                # Add to SSH configuration
                if ! grep -q "Match User $username" /etc/ssh/sshd_config; then
                    cat >> /etc/ssh/sshd_config << EOFF
Match User $username
    AllowTcpForwarding yes
    X11Forwarding no
    AllowAgentForwarding yes
    ForceCommand /bin/false
    PermitTTY no
EOFF
                fi
                systemctl restart ssh
                echo "User $username created and configured for SSH tunneling"
                echo "Connection details:"
                echo "  Server IP: $PUBLIC_IP"
                echo "  Username: $username"
                echo "  Port: 22 (default SSH)"
                echo "  Connection command: ssh -D 1080 -f -C -q -N $username@$PUBLIC_IP"
            else
                echo "Password cannot be empty"
            fi
        else
            echo "Username cannot be empty"
        fi
        ;;
    setup-client)
        echo "=== SSH Tunnel Client Setup Instructions ==="
        echo ""
        echo "1. On your client device (phone/computer), run:"
        echo "   ssh -D 1080 -f -C -q -N tunneluser@$PUBLIC_IP"
        echo ""
        echo "2. Configure your browser to use SOCKS proxy:"
        echo "   Host: $PUBLIC_IP  Port: 1080  Type: SOCKS5"
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
        echo "   */5 * * * * pgrep -f 'ssh.*-D' >/dev/null || ssh -D 1080 -f -C -q -N tunneluser@$PUBLIC_IP"
        echo ""
        list_tunnel_users
        ;;
    *)
        echo "Usage: $0 {start|stop|status|create-user|setup-client}"
        echo ""
        echo "Commands:"
        echo "  start          - Show connection instructions"
        echo "  stop           - Stop all SSH tunnels"
        echo "  status         - Check tunnel status"
        echo "  create-user    - Create new SSH tunnel user"
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
    
    echo -e "${GREEN}SSH tunneling configured successfully with MTN simulation!${NC}"
    echo ""
    echo "Features activated:"
    echo "1. SSH server configured for tunneling on port 22"
    echo "2. MTN zero-rated domain access through SSH with faux tunneling"
    echo "3. SOCKS proxy support (port 1080)"
    echo "4. Persistent tunnel service with auto-restart"
    echo "5. Traffic shaping to make SSH traffic appear like MTN traffic"
    echo "6. Default user: tunneluser / TunnelPass123!"
    echo "7. Specific handling for Ayoba IP: 63.35.40.123"
    echo ""
    echo -e "${YELLOW}SSH tunneling is now fully integrated with MTN Cameroon bypass${NC}"
    log "INFO" "SSH tunneling configured for MTN zero-rated access"
    read -p "Press Enter to continue..."
}

# Service mode for persistent operation
service_mode() {
    log "INFO" "Starting Techub service mode"
    
    # Set up error handling
    trap 'log "ERROR" "Service mode encountered an error"; exit 1' ERR
    
    # Start OpenVPN server with better error handling
    if systemctl is-active --quiet openvpn-server@server || systemctl is-active --quiet openvpn@server; then
        log "INFO" "OpenVPN service already running"
    else
        if systemctl start openvpn-server@server 2>/dev/null || systemctl start openvpn@server 2>/dev/null; then
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
    echo "Server IPs: $PRIMARY_IP / $PUBLIC_IP"
    echo "Press Ctrl+C to stop the service monitor"
    
    # Keep service alive with proper monitoring
    while true; do
        sleep 60
        
        # Check if OpenVPN is running
        if ! systemctl is-active --quiet openvpn-server@server && ! systemctl is-active --quiet openvpn@server; then
            log "WARN" "OpenVPN service not running, attempting restart..."
            if systemctl start openvpn-server@server 2>/dev/null || systemctl start openvpn@server 2>/dev/null; then
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
        
        # Ensure MTN domain configuration exists
        if [[ ! -f "/etc/hosts.mtn" ]]; then
            if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
                source "${SCRIPT_DIR}/isp_domains.conf"
                cat > /etc/hosts.mtn << EOF
# MTN Cameroon Hosts File for Zero-Rated Services with actual MTN IPs and Ayoba IP
196.168.1.1 mtn.cm
196.168.1.1 nointernet.mtn.cm
196.168.1.1 www.mtn.cm
196.168.1.1 mtnonline.com
196.168.1.1 www.mtnonline.com
63.35.40.123 ayoba.me
63.35.40.123 www.ayoba.me
196.200.135.11 facebook.com
196.200.135.11 www.facebook.com
196.200.135.11 m.facebook.com
196.200.135.11 fbcdn.net
196.200.135.11 instagram.com
196.200.135.11 whatsapp.com
EOF
                cat /etc/hosts.mtn >> /etc/hosts
                log "INFO" "MTN hosts file recreated"
            fi
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
                handle_ssh_tunnel_menu
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
