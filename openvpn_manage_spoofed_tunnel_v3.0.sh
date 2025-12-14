#!/bin/bash
# OpenVPN Faux Tunnel Management System v3.0
# Purpose: Educational OpenVPN infrastructure with "faux tunneling" for lab simulations
#          and internal network testing (authorized penetration testing only)

# Strict error handling
set -euo pipefail

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root" >&2
        exit 1
    fi
}

# Main initialization function
initialize_system() {
    check_root
    
    echo "Initializing Faux Tunnel System..."
    
    # Create directories
    mkdir -p /etc/openvpn/faux-tunnel/clients
    mkdir -p /etc/openvpn/faux-tunnel/ccd
    mkdir -p /etc/openvpn/faux-tunnel/backups
    mkdir -p /var/log
    
    # Install dependencies
    echo "Installing dependencies..."
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y openvpn easy-rsa iptables-persistent dnsutils net-tools
    elif command -v yum &> /dev/null; then
        yum install -y epel-release
        yum install -y openvpn easy-rsa iptables-services bind-utils net-tools
    else
        echo "WARNING: Unsupported package manager. Please install OpenVPN manually."
    fi
    
    # Setup EasyRSA
    echo "Setting up EasyRSA..."
    mkdir -p /etc/openvpn/easy-rsa
    if [[ -d "/usr/share/easy-rsa/3" ]]; then
        cp -r /usr/share/easy-rsa/3/* /etc/openvpn/easy-rsa/
    elif [[ -d "/usr/share/easy-rsa" ]]; then
        cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    else
        echo "Installing easy-rsa package..."
        if command -v apt-get &> /dev/null; then
            apt-get install -y easy-rsa
            cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
        fi
    fi
    
    # Initialize PKI
    cd /etc/openvpn/easy-rsa
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
    cat > /etc/openvpn/faux-tunnel/isp_domains.conf << 'EOF'
# ISP Domain Configuration for Faux Tunneling Lab
zero_rated_domains=mtn.cm,nointernet.mtn.cm,www.facebook.com,www.ayoba.me,mtnonline.com
zero_rated_domains_alt=mtn.cm,ayoba.me,nointernet.mtn.cm,m.facebook.com
additional_domains=instagram.com,whatsapp.com
policy_group_social=www.facebook.com,www.ayoba.me,m.facebook.com,instagram.com,whatsapp.com
policy_group_carrier=mtn.cm,nointernet.mtn.cm,mtnonline.com
EOF
    
    # Create client template
    cat > /etc/openvpn/faux-tunnel/client-template.ovpn << 'EOF'
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
    
    echo "System initialized successfully!"
    echo "Next steps:"
    echo "  1. Generate clients with: $0 generate-client <client-name>"
    echo "  2. Start the service with: $0 start"
}

# Generate client certificate and configuration
generate_client() {
    local client_name="$1"
    
    if [[ -z "$client_name" ]]; then
        echo "ERROR: Client name is required" >&2
        return 1
    fi
    
    echo "Generating client configuration for: $client_name"
    
    cd /etc/openvpn/easy-rsa
    
    # Generate client certificate
    ./easyrsa gen-req "$client_name" nopass
    echo "yes" | ./easyrsa sign-req client "$client_name"
    
    # Create client directory
    mkdir -p "/etc/openvpn/faux-tunnel/clients/$client_name"
    
    # Create client config with embedded certificates
    local client_config="/etc/openvpn/faux-tunnel/clients/$client_name/$client_name.ovpn"
    cp /etc/openvpn/faux-tunnel/client-template.ovpn "$client_config"
    
    # Embed certificates
    sed -i '/<ca>/r/etc/openvpn/easy-rsa/pki/ca.crt' "$client_config"
    sed -i '/<cert>/r/etc/openvpn/easy-rsa/pki/issued/'"$client_name"'.crt' "$client_config"
    sed -i '/<key>/r/etc/openvpn/easy-rsa/pki/private/'"$client_name"'.key' "$client_config"
    sed -i '/<tls-auth>/r/etc/openvpn/easy-rsa/pki/ta.key' "$client_config"
    
    echo "Client configuration created: $client_config"
}

# Start OpenVPN service
start_service() {
    echo "Starting OpenVPN service..."
    systemctl start openvpn@server
    echo "OpenVPN service started"
}

# Stop OpenVPN service
stop_service() {
    echo "Stopping OpenVPN service..."
    systemctl stop openvpn@server
    echo "OpenVPN service stopped"
}

# Main execution
case "${1:-help}" in
    init)
        initialize_system
        ;;
    generate-client)
        if [[ $# -lt 2 ]]; then
            echo "ERROR: Client name required" >&2
            exit 1
        fi
        generate_client "$2"
        ;;
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    *)
        echo "OpenVPN Faux Tunnel Management System v3.0"
        echo "Usage: $0 {init|generate-client <name>|start|stop}"
        echo ""
        echo "Commands:"
        echo "  init              Initialize the entire system"
        echo "  generate-client   Generate new client configuration"
        echo "  start             Start OpenVPN service"
        echo "  stop              Stop OpenVPN service"
        ;;
esac
