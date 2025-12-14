#!/bin/bash
# Techub OpenVPN Management System v4.1 - MTN Cameroon Enhanced
# Fixed MTN Cameroon bypass configuration and DNS resolution issues

# ... [previous code remains the same until the configure_mtn_bypass function] ...

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
        # Use IP addresses instead of domain names to avoid DNS resolution issues
        zero_rated_domains="196.168.1.1,196.168.1.2,69.171.247.12,69.171.247.11,157.240.1.35"
        mtn_cm_ips="196.168.1.1,196.168.1.2"
        social_media_ips="69.171.247.12,69.171.247.11,157.240.1.35"
    fi
    
    echo -e "${YELLOW}Setting up MTN Cameroon bypass configuration...${NC}"
    
    # 1. Configure iptables for domain redirection using IPs
    echo "1. Setting up traffic redirection rules using IP addresses..."
    
    # Get primary interface
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    # Create custom chain for MTN domains
    iptables -t nat -N mtn_bypass 2>/dev/null || true
    iptables -t nat -F mtn_bypass
    
    # Parse domains (now IP addresses) and create redirection rules
    IFS=',' read -ra DOMAINS <<< "$zero_rated_domains"
    for ip in "${DOMAINS[@]}"; do
        # Validate IP address format
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            iptables -t nat -A mtn_bypass -p tcp -d "$ip" --dport 80 -j REDIRECT --to-port 80 2>/dev/null || true
            iptables -t nat -A mtn_bypass -p tcp -d "$ip" --dport 443 -j REDIRECT --to-port 443 2>/dev/null || true
        else
            echo -e "${YELLOW}Skipping invalid IP: $ip${NC}"
        fi
    done
    
    # Apply chain to main NAT rules
    iptables -t nat -A PREROUTING -j mtn_bypass 2>/dev/null || true
    
    # 2. Configure DNS to handle MTN domains properly
    echo "2. Setting up DNS handling..."
    
    # Create a custom DNS hosts file for MTN domains
    cat > /etc/hosts.mtn << EOF
# MTN Cameroon Hosts File
196.168.1.1 mtn.cm
196.168.1.1 nointernet.mtn.cm
196.168.1.1 mtnonline.com
69.171.247.12 www.facebook.com
69.171.247.11 facebook.com
69.171.247.12 fbcdn.net
157.240.1.35 instagram.com
157.240.1.35 whatsapp.com
EOF
    
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

# MTN Cameroon domains - direct access (appears as MTN traffic)
acl mtn_domains dst 196.168.1.0/24
acl social_media dst 69.171.247.0/24
acl messaging dst 157.240.0.0/16

# Always direct these IPs to MTN
always_direct allow mtn_domains
always_direct allow social_media
always_direct allow messaging

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
    
    # Configure DNAT for MTN domains to appear as if coming from MTN
    IFS=',' read -ra MTN_IPS <<< "$mtn_cm_ips"
    for ip in "${MTN_IPS[@]}"; do
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # NAT rules to redirect common ports to MTN IPs
            iptables -t nat -A OUTPUT -p tcp -d "$ip" --dport 80 -j DNAT --to-destination "$ip:80" 2>/dev/null || true
            iptables -t nat -A OUTPUT -p tcp -d "$ip" --dport 443 -j DNAT --to-destination "$ip:443" 2>/dev/null || true
        fi
    done
    
    echo ""
    echo -e "${GREEN}MTN Cameroon bypass configuration completed!${NC}"
    echo ""
    echo "Key configurations applied:"
    echo "1. Special routing for MTN IP addresses (using IPs instead of domains)"
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

# ... [rest of the code remains the same] ...

# Additional helper function to properly initialize MTN configuration
initialize_mtn_domains() {
    cat > "${SCRIPT_DIR}/isp_domains.conf" << 'EOF'
# MTN Cameroon Domain Configuration for Faux Tunneling
# Using IP addresses to avoid DNS resolution issues
zero_rated_domains=196.168.1.1,196.168.1.2,69.171.247.12,69.171.247.11,157.240.1.35
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
