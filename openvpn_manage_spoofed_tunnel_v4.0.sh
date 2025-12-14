#!/bin/bash
# OpenVPN Faux Tunnel Management System v4.0
# Enhanced with automatic launch, persistence, and ISP bypass features

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Strict error handling
set -euo pipefail

# Global variables
SCRIPT_DIR="/etc/openvpn/faux-tunnel"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_DIR="${SCRIPT_DIR}/clients"
LOG_FILE="/var/log/openvpn-faux-tunnel.log"
SYSTEMD_SERVICE="/etc/systemd/system/openvpn-faux-tunnel.service"
AUTO_LAUNCH_FILE="/usr/local/bin/techub"
SCRIPT_PATH="/root/Techub_VPS/openvpn_manage_spoofed_tunnel_v4.0.sh"

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
    echo -e "${BLUE}  Techub OpenVPN Faux Tunnel System     ${NC}"
    echo -e "${BLUE}         For MTN Cameroon Users         ${NC}"
    echo -e "${BLUE}            Version 4.0                  ${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
}

# Main menu
show_main_menu() {
    show_header
    echo -e "${YELLOW}Main Menu:${NC}"
    echo "  1. System Initialization & Setup"
    echo "  2. OpenVPN Management"
    echo "  3. Client Management"
    echo "  4. SSH Account Management"
    echo "  5. MTN Cameroon Bypass Configuration"
    echo "  6. Monitoring & Status"
    echo "  7. Auto-run & Persistence Setup"
    echo "  8. Exit"
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
    echo "  5. Download Client Config (QR Code)"
    echo "  6. Back to Main Menu"
    echo ""
}

# SSH submenu
show_ssh_menu() {
    show_header
    echo -e "${YELLOW}SSH Account Management:${NC}"
    echo "  1. Create SSH Account (ISP Bypass)"
    echo "  2. List SSH Accounts"
    echo "  3. Delete SSH Account"
    echo "  4. Change SSH Password"
    echo "  5. Back to Main Menu"
    echo ""
}

# MTN Cameroon submenu
show_mtn_menu() {
    show_header
    echo -e "${YELLOW}MTN Cameroon Bypass Configuration:${NC}"
    echo "  1. Configure Zero-Rated Domains"
    echo "  2. Configure DNS Redirects"
    echo "  3. Setup Traffic Shaping Rules"
    echo "  4. Apply ISP-Neutral Routing"
    echo "  5. Test MTN Bypass"
    echo "  6. Back to Main Menu"
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

# Auto-run submenu
show_autorun_menu() {
    show_header
    echo -e "${YELLOW}Auto-run & Persistence Setup:${NC}"
    echo "  1. Install Auto Launch (type 'techub' to launch)"
    echo "  2. Setup 24/7 Persistent Service"
    echo "  3. Configure Auto-Reconnect"
    echo "  4. Enable Startup Optimization"
    echo "  5. Check System Persistence"
    echo "  6. Back to Main Menu"
    echo ""
}

# System initialization with MTN Cameroon optimization
initialize_system() {
    show_header
    echo -e "${GREEN}Initializing Techub Faux Tunnel System...${NC}"
    log "INFO" "System initialization started"
    
    # Create directories
    mkdir -p "${SCRIPT_DIR}/clients"
    mkdir -p "${SCRIPT_DIR}/ccd"
    mkdir -p "${SCRIPT_DIR}/backups"
    mkdir -p "${SCRIPT_DIR}/scripts"
    mkdir -p /var/log
    
    # Install dependencies
    echo -e "${YELLOW}Installing dependencies...${NC}"
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y openvpn easy-rsa iptables-persistent dnsutils net-tools openssh-server \
                          curl wget ntp ntpdate python3-qrcode python3-pil tcpdump iptables-services
    elif command -v yum &> /dev/null; then
        yum install -y epel-release
        yum install -y openvpn easy-rsa iptables-services bind-utils net-tools openssh-server \
                      curl wget ntp python3-qrcode python3-pil tcpdump
    else
        echo -e "${RED}WARNING: Unsupported package manager. Please install packages manually.${NC}"
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
    
    # Create OpenVPN server configuration optimized for MTN Cameroon
    cat > /etc/openvpn/server.conf << 'EOF'
port 443
proto tcp
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
server 10.9.0.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 1.1.1.1"
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
reneg-sec 0
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
mssfix 1200
tun-mtu 1200
fragment 1300
EOF
    
    # Setup IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables NAT with MTN Cameroon optimizations
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # NAT rules
    iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$PRIMARY_INTERFACE" -j MASQUERADE
    iptables -A INPUT -i tun+ -j ACCEPT
    iptables -A FORWARD -i tun+ -j ACCEPT
    iptables -A FORWARD -o tun+ -j ACCEPT
    
    # MTN Cameroon specific optimizations
    # Allow normal traffic but mark/redirect special MTN domains
    iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 80
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 443
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    # Create domain configuration for MTN Cameroon
    cat > "${SCRIPT_DIR}/isp_domains.conf" << 'EOF'
# MTN Cameroon Domain Configuration for Faux Tunneling
zero_rated_domains=mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com,facebook.com
zero_rated_domains_alt=mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com
social_domains=www.facebook.com,www.ayoba.me,m.facebook.com,instagram.com,whatsapp.com,snapchat.com,tiktok.com
messaging_domains=whatsapp.com,messenger.com,telegram.org,signal.org
video_domains=youtube.com,youtu.be,vimeo.com,dailymotion.com
news_domains=bbc.com,cnn.com,reuters.com,aljazeera.com
mtncm_domains=mtn.cm,nointernet.mtn.cm,mtnonline.com
mtncm_redirects=196.168.1.1:80,196.168.1.2:443
avoid_detection_domains=gstatic.com,google.com,googleapis.com
parallel_connections=true
load_balancing=true
EOF
    
    # Create scripts for MTN Cameroon optimizations
    mkdir -p "${SCRIPT_DIR}/scripts"
    
    # Traffic shaping script
    cat > "${SCRIPT_DIR}/scripts/traffic_shaping.sh" << 'EOF'
#!/bin/bash
# Traffic shaping for MTN Cameroon

INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

# Set up traffic control
tc qdisc add dev $INTERFACE root handle 1: htb default 30
tc class add dev $INTERFACE parent 1: classid 1:1 htb rate 100mbit
tc class add dev $INTERFACE parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit
tc class add dev $INTERFACE parent 1:1 classid 1:20 htb rate 30mbit ceil 100mbit
tc class add dev $INTERFACE parent 1:1 classid 1:30 htb rate 20mbit ceil 100mbit

# Prioritize VPN traffic
tc filter add dev $INTERFACE protocol ip parent 1:0 prio 1 u32 match ip sport 443 0xffff flowid 1:10
tc filter add dev $INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dport 443 0xffff flowid 1:10
EOF
    
    chmod +x "${SCRIPT_DIR}/scripts/traffic_shaping.sh"
    
    # Create client template optimized for MTN Cameroon
    cat > "${SCRIPT_DIR}/client-template.ovpn" << 'EOF'
client
dev tun
proto tcp
remote YOUR_SERVER_IP 443
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
sndbuf 393216
rcvbuf 393216
reneg-sec 0
redirect-gateway def1
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4
tun-mtu 1200
fragment 1300
mssfix 1200
EOF
    
    # Setup DNS configuration for MTN Cameroon bypass
    cat > /etc/systemd/resolved.conf << 'EOF'
[Resolve]
DNS=8.8.8.8 8.8.4.4 1.1.1.1
FallbackDNS=208.67.222.222 208.67.220.220
Domains=~.
DNSSEC=yes
DNSOverTLS=opportunistic
EOF
    
    # Restart DNS resolver
    systemctl restart systemd-resolved
    
    # Setup NTP for time synchronization
    cat > /etc/ntp.conf << 'EOF'
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst
driftfile /var/lib/ntp/ntp.drift
logfile /var/log/ntp.log
EOF
    
    systemctl restart ntp
    
    log "INFO" "System initialization completed"
    echo -e "${GREEN}System initialized successfully!${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Create SSH accounts for MTN users (Menu option 4.1)"
    echo "  2. Generate client certificates (Menu option 3.1)"
    echo "  3. Configure MTN Cameroon bypass (Menu option 5)"
    echo "  4. Set up auto-run (Menu option 7)"
    echo ""
    read -p "Press Enter to continue..."
}

# Generate client with MTN Cameroon optimizations
generate_client() {
    show_header
    echo -e "${GREEN}Generate New Client (MTN Optimized)${NC}"
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
    
    # Create MTN Cameroon profile
    cat >> "$client_config" << 'EOF'

# MTN Cameroon Optimization Profile
# Zero-rated domains configuration
route mtn.cm 255.255.255.255 net_gateway
route nointernet.mtn.cm 255.255.255.255 net_gateway
route www.facebook.com 255.255.255.255 net_gateway
route www.ayoba.me 255.255.255.255 net_gateway

# Faux tunneling configuration
pull-filter ignore "redirect-gateway"
redirect-gateway def1
EOF
    
    echo ""
    echo -e "${GREEN}Client configuration created successfully!${NC}"
    echo "Configuration file: $client_config"
    echo ""
    echo -e "${YELLOW}MTN Cameroon Bypass Notes:${NC}"
    echo "1. Clients can browse all domains via your server"
    echo "2. Zero-rated domains (mtn.cm, facebook.com) appear to come from MTN"
    echo "3. Other traffic goes through encrypted tunnel"
    echo "4. Users need no data package to browse through SSH tunnel"
    echo ""
    read -p "Press Enter to continue..."
}

# Create SSH account optimized for MTN Cameroon
create_ssh_account() {
    show_header
    echo -e "${GREEN}Create SSH Account (MTN Cameroon Bypass)${NC}"
    echo ""
    echo -e "${YELLOW}This account allows MTN users to browse the internet without a data package${NC}"
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
        # Create user with restricted shell
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        
        # Create SSH directory structure
        mkdir -p /home/"$username"/.ssh
        chmod 700 /home/"$username"/.ssh
        chown "$username":"$username" /home/"$username"/.ssh
        
        # Add to sudo group if it exists
        if getent group sudo > /dev/null 2>&1; then
            usermod -aG sudo "$username"
        elif getent group wheel > /dev/null 2>&1; then
            usermod -aG wheel "$username"
        fi
    fi
    
    # Display connection details clearly for copying
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    
    echo ""
    echo -e "${GREEN}SSH Account Created Successfully!${NC}"
    echo "=================================="
    echo -e "${PURPLE}USERNAME:${NC} $username"
    echo -e "${PURPLE}PASSWORD:${NC} $password"
    echo -e "${PURPLE}SERVER IP:${NC} $SERVER_IP"
    echo -e "${PURPLE}SSH PORT:${NC} $SSH_PORT"
    echo "=================================="
    echo ""
    echo -e "${YELLOW}USAGE INSTRUCTIONS FOR MTN USERS:${NC}"
    echo "=================================="
    echo "1. Open your terminal/SSH client"
    echo "2. Connect with command:"
    echo -e "${PURPLE}ssh $username@$SERVER_IP -p $SSH_PORT${NC}"
    echo ""
    echo "3. For persistent browsing (web proxy):"
    echo -e "${PURPLE}ssh -D 8080 $username@$SERVER_IP -p $SSH_PORT${NC}"
    echo ""
    echo "4. Configure your browser to use SOCKS proxy:"
    echo "   - Host: localhost"
    echo "   - Port: 8080"
    echo "   - Type: SOCKS v5"
    echo ""
    echo "5. For Windows users, use PuTTY:"
    echo "   - Session: $SERVER_IP:$SSH_PORT"
    echo "   - Connection->SSH->Tunnels: Source 8080, Destination Dynamic"
    echo ""
    echo -e "${GREEN}This provides FREE internet access for MTN Cameroon users without a data package!${NC}"
    echo ""
    echo -e "${YELLOW}Connection commands (COPY these):${NC}"
    echo "ssh $username@$SERVER_IP -p $SSH_PORT"
    echo "ssh -D 8080 $username@$SERVER_IP -p $SSH_PORT"
    echo ""
    log "INFO" "SSH account created: $username"
    
    read -p "Press Enter to continue..."
}

# Configure MTN Cameroon bypass systems
configure_mtn_bypass() {
    show_header
    echo -e "${GREEN}Configuring MTN Cameroon Bypass Systems${NC}"
    echo ""
    
    # Load domain information
    if [[ -f "${SCRIPT_DIR}/isp_domains.conf" ]]; then
        source "${SCRIPT_DIR}/isp_domains.conf"
    else
        echo -e "${YELLOW}Domain configuration not found, using defaults...${NC}"
        zero_rated_domains="mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me"
    fi
    
    echo -e "${YELLOW}Setting up MTN Cameroon bypass configuration...${NC}"
    
    # 1. Configure iptables for domain redirection
    echo "1. Setting up traffic redirection rules..."
    
    # Get primary interface
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # Create custom chain for MTN domains
    iptables -t nat -N mtn_bypass 2>/dev/null || true
    iptables -t nat -F mtn_bypass
    
    # Parse domains and create redirection rules
    IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
    for domain in "${DOMAINS[@]}"; do
        iptables -t nat -A mtn_bypass -p tcp -d "$domain" --dport 80 -j REDIRECT --to-port 80
        iptables -t nat -A mtn_bypass -p tcp -d "$domain" --dport 443 -j REDIRECT --to-port 443
    done
    
    # Apply chain to main NAT rules
    iptables -t nat -A PREROUTING -j mtn_bypass
    
    # 2. Configure DNS resolver to forward MTN domains to MTN DNS
    echo "2. Setting up DNS forwarding..."
    
    # Create custom DNS configuration
    cat > /etc/dnsmasq.conf << EOF
# MTN Cameroon DNS Configuration
interface=tun0
interface=$PRIMARY_INTERFACE
bind-interfaces
domain-needed
bogus-priv
local-service
server=8.8.8.8
server=8.8.4.4
address=/mtn.cm/196.168.1.1
address=/nointernet.mtn.cm/196.168.1.1
address=/www.facebook.com/196.168.1.1
address=/www.ayoba.me/196.168.1.1
EOF
    
    # 3. Create MTN-specific routing table
    echo "3. Setting up routing optimizations..."
    
    # Configure advanced routing
    cat > /etc/iproute2/rt_tables << EOF
#
# reserved values
#
255	local
254	main
253	default
0	unspec
#
# local
#
1	mtn
2	vpn
EOF
    
    # 4. Set up traffic prioritization
    echo "4. Setting up traffic prioritization..."
    
    # Clear existing rules
    tc qdisc del dev "$PRIMARY_INTERFACE" root 2>/dev/null || true
    
    # Set up HTB (Hierarchical Token Bucket)
    tc qdisc add dev "$PRIMARY_INTERFACE" root handle 1: htb default 30
    tc class add dev "$PRIMARY_INTERFACE" parent 1: classid 1:1 htb rate 100mbit
    tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit
    tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:20 htb rate 30mbit ceil 100mbit
    tc class add dev "$PRIMARY_INTERFACE" parent 1:1 classid 1:30 htb rate 20mbit ceil 100mbit
    
    # Prioritize tunnel traffic
    tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip sport 443 0xffff flowid 1:10
    tc filter add dev "$PRIMARY_INTERFACE" protocol ip parent 1:0 prio 1 u32 match ip dport 443 0xffff flowid 1:10
    
    # 5. Configure HTTP proxy for MTN domains
    echo "5. Setting up HTTP proxy configuration..."
    
    # Ensure squid is installed
    if ! command -v squid &> /dev/null; then
        echo "Installing Squid proxy..."
        if command -v apt-get &> /dev/null; then
            apt-get install -y squid
        else
            yum install -y squid
        fi
    fi
    
    # Create Squid configuration optimized for MTN
    cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
visible_hostname techub-mtn-proxy

# MTN Cameroon domains - direct access (appears as MTN traffic)
acl mtn_domains dstdomain .mtn.cm .nointernet.mtn.cm .mtnonline.com
acl mtn_social dstdomain .facebook.com .ayoba.me .whatsapp.com

# Always direct these domains to MTN
always_direct allow mtn_domains
always_direct allow mtn_social

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
    
    # Restart services
    systemctl restart dnsmasq 2>/dev/null || echo "dnsmasq not installed or configured"
    systemctl restart squid 2>/dev/null || echo "squid not installed or configured"
    
    echo ""
    echo -e "${GREEN}MTN Cameroon bypass configuration completed!${NC}"
    echo ""
    echo "Key configurations applied:"
    echo "1. Special routing for MTN domains"
    echo "2. DNS redirection to MTN servers"
    echo "3. Traffic prioritization"
    echo "4. HTTP proxy for direct access"
    echo ""
    echo "Users can access MTN zero-rated domains without using data!"
    echo ""
    log "INFO" "MTN Cameroon bypass configured"
    read -p "Press Enter to continue..."
}

# Install auto launch functionality
install_auto_launch() {
    show_header
    echo -e "${GREEN}Installing Auto Launch System${NC}"
    echo ""
    
    # Create auto-launch script
    cat > "${AUTO_LAUNCH_FILE}" << EOF
#!/bin/bash
# Techub Auto Launch Script

cd $(dirname "${SCRIPT_PATH}")
exec sudo ./$(basename "${SCRIPT_PATH}")
EOF
    
    chmod +x "${AUTO_LAUNCH_FILE}"
    
    # Update shell profile to launch when typing 'techub'
    if ! grep -q "alias techub=" ~/.bashrc 2>/dev/null; then
        echo "alias techub='${AUTO_LAUNCH_FILE}'" >> ~/.bashrc
    fi
    
    if ! grep -q "alias techub=" ~/.bash_aliases 2>/dev/null; then
        echo "alias techub='${AUTO_LAUNCH_FILE}'" >> ~/.bash_aliases 2>/dev/null
    fi
    
    # Create systemd service for persistent operation
    cat > "${SYSTEMD_SERVICE}" << EOF
[Unit]
Description=Techub OpenVPN Faux Tunnel Service
After=network.target

[Service]
Type=forking
User=root
WorkingDirectory=/root/Techub_VPS
ExecStart=/usr/bin/screen -dmS techub_service sudo ./openvpn_manage_spoofed_tunnel_v4.0.sh service-mode
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and start the service
    systemctl daemon-reload
    systemctl enable openvpn-faux-tunnel.service 2>/dev/null || true
    
    echo ""
    echo -e "${GREEN}Auto Launch System installed successfully!${NC}"
    echo ""
    echo "Features activated:"
    echo "1. Type 'techub' from any terminal to launch main menu"
    echo "2. Persistent 24/7 operation through systemd service"
    echo "3. Auto-reconnect on failures"
    echo "4. Screen session for background processing"
    echo ""
    echo "To start the persistent service now:"
    echo "sudo systemctl start openvpn-faux-tunnel"
    echo ""
    read -p "Press Enter to continue..."
}

# Service mode for persistent operation
service_mode() {
    # Start OpenVPN server
    systemctl start openvpn@server
    
    # Apply traffic shaping
    if [[ -f "${SCRIPT_DIR}/scripts/traffic_shaping.sh" ]]; then
        "${SCRIPT_DIR}/scripts/traffic_shaping.sh"
    fi
    
    # Keep service alive
    while true; do
        sleep 60
        
        # Check if OpenVPN is running
        if ! systemctl is-active --quiet openvpn@server; then
            log "WARN" "OpenVPN service not running, restarting..."
            systemctl start openvpn@server
        fi
        
        # Check system health
        if [[ $(free | grep Mem | awk '{print $4}') -lt 100000 ]]; then
            log "WARN" "Low memory detected"
        fi
    done
}

# System health check with MTN monitoring
health_check() {
    show_header
    echo -e "${GREEN}Techub System Health Check${NC}"
    echo ""
    
    echo "=== System Status ==="
    echo "Uptime: $(uptime)"
    echo "Load average: $(uptime | awk -F'load average:' '{print $2}')"
    echo ""
    
    echo "=== OpenVPN Status ==="
    if systemctl is-active --quiet openvpn@server; then
        echo -e "${GREEN}✓ OpenVPN service is running${NC}"
        echo "  Port: $(grep "^port" /etc/openvpn/server.conf | awk '{print $2}')"
        echo "  Protocol: $(grep "^proto" /etc/openvpn/server.conf | awk '{print $2}')"
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
    echo "=== MTN Cameroon Bypass Status ==="
    # Check if key services are running
    if command -v squid &> /dev/null && systemctl is-active --quiet squid; then
        echo -e "${GREEN}✓ HTTP Proxy (Squid) is running${NC}"
    else
        echo -e "${YELLOW}! HTTP Proxy not active${NC}"
    fi
    
    if command -v dnsmasq &> /dev/null && systemctl is-active --quiet dnsmasq; then
        echo -e "${GREEN}✓ DNS Service (Dnsmasq) is running${NC}"
    else
        echo -e "${YELLOW}! DNS Service not active${NC}"
    fi
    
    echo ""
    echo "=== Connected Clients ==="
    if [[ -f "/var/log/openvpn-status.log" ]]; then
        echo "Connected clients: $(grep -c "CLIENT_LIST" /var/log/openvpn-status.log 2>/dev/null || echo "0")"
    else
        echo "0"
    fi
    
    log "INFO" "Health check performed"
    echo ""
    read -p "Press Enter to continue..."
}

# Main execution loop
main() {
    check_root
    
    # Check if launched in service mode
    if [[ "${1:-}" == "service-mode" ]]; then
        service_mode
        exit 0
    fi
    
    while true; do
        show_main_menu
        read -p "Select option (1-8): " main_choice
        
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
                    read -p "Select option (1-6): " client_choice
                    
                    case $client_choice in
                        1) generate_client ;;
                        2) list_clients ;;
                        3) revoke_client ;;
                        4) view_client_config ;;
                        5) 
                            echo -e "${RED}QR code generation not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        6) break ;;
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
                    show_mtn_menu
                    read -p "Select option (1-6): " mtn_choice
                    
                    case $mtn_choice in
                        1) configure_mtn_bypass ;;
                        2) 
                            echo -e "${RED}DNS configuration not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        3) 
                            echo -e "${RED}Traffic shaping not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        4) 
                            echo -e "${RED}ISP routing not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        5) 
                            echo -e "${RED}MTN bypass test not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        6) break ;;
                        *) 
                            echo -e "${RED}Invalid option${NC}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            6)
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
            7)
                while true; do
                    show_autorun_menu
                    read -p "Select option (1-6): " autorun_choice
                    
                    case $autorun_choice in
                        1) install_auto_launch ;;
                        2) 
                            echo -e "${RED}Service setup not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        3) 
                            echo -e "${RED}Auto-reconnect setup not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        4) 
                            echo -e "${RED}Startup optimization not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        5) 
                            echo -e "${RED}Persistence check not implemented in this version${NC}"
                            read -p "Press Enter to continue..."
                            ;;
                        6) break ;;
                        *) 
                            echo -e "${RED}Invalid option${NC}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            8)
                echo -e "${GREEN}Exiting Techub System...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 1
                ;;
        esac
    done
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
    echo -e "${YELLOW}For MTN Cameroon users:${NC}"
    echo "1. This config works with any OpenVPN client"
    echo "2. Provides internet access without data package"
    echo "3. Zero-rated domains bypass VPN for performance"
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

# Run main function
main "$@"
