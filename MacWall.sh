#!/bin/bash

# Real-time Firewall Monitor for macOS --- ヽ༼ ຈل͜ຈ༼ ▀̿̿Ĺ̯̿̿▀̿ ̿༽Ɵ͆ل͜Ɵ͆ ༽ﾉ Meowww
# Uses built-in tools: netstat, lsof, pfctl, nettop
# Run with: chmod +x firewall_monitor.sh && ./firewall_monitor.sh
# AI 	╰( ͡° ͜ʖ ͡° )つ──☆*:・ﾟ MAGIC . 

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
REFRESH_INTERVAL=3
LOG_FILE="$HOME/firewall_monitor.log"
SUSPICIOUS_PORTS=(22 23 25 53 80 110 143 443 993 995 1433 3306 3389 5432 6379)

# Threat Intelligence Configuration
ENABLE_IP_ANALYSIS=true
HIGH_RISK_COUNTRIES=("China" "Russia" "North Korea" "Iran" "Afghanistan")
CLOUD_PROVIDERS=("amazonaws" "azure" "googlecloud" "digitalocean" "vultr" "linode" "hetzner")
MAX_CONNECTIONS_PER_IP=10
DEEP_ANALYSIS_MODE=false  # Set to true for more detailed analysis (slower)

# ARP Spoof Detection Configuration
ENABLE_ARP_MONITORING=true
ARP_TABLE_FILE="/tmp/arp_baseline_$"
ARP_LOG_FILE="$HOME/arp_security.log"
ARP_CHANGE_THRESHOLD=3  # Number of MAC changes before alerting
GATEWAY_MAC_FILE="/tmp/gateway_mac_$"

# Function to print header
print_header() {
    clear
    echo -e "${WHITE}================================================${NC}"
    echo -e "${WHITE}    ---- MacWall - Realtime 🔥Firewall ----${NC}"
    echo -e "${WHITE}    $(date)${NC}"
    echo -e "${WHITE}    Refresh every ${REFRESH_INTERVAL}s | Log: ${LOG_FILE}${NC}"
    echo -e "${WHITE}================================================${NC}"
    echo
}

# Function to check firewall status
check_firewall_status() {
    echo -e "${CYAN}🔥 FIREWALL STATUS${NC}"
    echo "----------------------------------------"

    # Check if pfctl is available and firewall is enabled
    if command -v pfctl >/dev/null 2>&1; then
        if sudo pfctl -s info >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Packet Filter (pfctl) is active${NC}"
            sudo pfctl -s info | head -5
        else
            echo -e "${YELLOW}⚠ Packet Filter (pfctl) status unclear${NC}"
        fi
    else
        echo -e "${RED}✗ pfctl not available${NC}"
    fi

    # Check Application Firewall
    if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "enabled"; then
        echo -e "${GREEN}✓ Application Firewall is enabled${NC}"
    else
        echo -e "${RED}✗ Application Firewall is disabled${NC}"
    fi

    echo
}

# Function to show active network connections
show_connections() {
    echo -e "${BLUE}🌐 ACTIVE NETWORK CONNECTIONS${NC}"
    echo "----------------------------------------"

    # Show listening ports and established connections
    echo -e "${WHITE}Listening Services:${NC}"
    netstat -an | grep LISTEN | head -10 | while read line; do
        port=$(echo $line | awk '{print $4}' | cut -d'.' -f5)
        if [[ " ${SUSPICIOUS_PORTS[@]} " =~ " ${port} " ]]; then
            echo -e "${YELLOW}$line${NC}"
        else
            echo -e "${GREEN}$line${NC}"
        fi
    done

    echo
    echo -e "${WHITE}Recent Established Connections:${NC}"
    netstat -an | grep ESTABLISHED | head -8
    echo
}

# Function to show processes with network activity
show_network_processes() {
    echo -e "${PURPLE}📊 PROCESSES WITH NETWORK ACTIVITY${NC}"
    echo "----------------------------------------"

    # Use lsof to show processes with network connections
    echo -e "${WHITE}Top Network-Active Processes:${NC}"
    lsof -i -P | grep -E "(LISTEN|ESTABLISHED)" | awk '{print $1, $2, $8, $9}' | sort | uniq -c | sort -nr | head -10
    echo
}

# Function to check VPN/Proxy services
check_vpn_proxy() {
    local ip=$1
    local hostname=$2
    local geo_asn=$3

    # Common VPN/Proxy indicators in hostnames
    local vpn_indicators=("vpn" "proxy" "tor" "exit" "relay" "tunnel" "anonymous" "hide" "mask")

    if [[ -n "$hostname" ]]; then
        for indicator in "${vpn_indicators[@]}"; do
            if echo "$hostname" | grep -qi "$indicator"; then
                echo -e "  ${YELLOW}⚠ Potential VPN/Proxy: $indicator detected${NC}"
                return 1
            fi
        done
    fi

    # Check common VPN/Proxy ASNs (basic check)
    if [[ -n "$geo_asn" ]]; then
        case "$geo_asn" in
            *"NordVPN"*|*"ExpressVPN"*|*"ProtonVPN"*|*"Mullvad"*)
                echo -e "  ${YELLOW}⚠ Known VPN Service detected${NC}"
                return 1
                ;;
        esac
    fi

    return 0
}

# Function to perform quick reputation check
check_ip_reputation() {
    local ip=$1

    echo -e "${WHITE}Reputation Check:${NC}"

    # Check for suspicious port combinations
    local suspicious_ports=$(netstat -an | grep "$ip" | awk '{print $5}' | cut -d':' -f2 | sort -u)
    local malware_ports=("1337" "31337" "6666" "6667" "4444" "8080" "9999")

    for port in $suspicious_ports; do
        if [[ " ${malware_ports[@]} " =~ " ${port} " ]]; then
            echo -e "  ${RED}⚠ Connection to known malware port: $port${NC}"
            return 1
        fi
    done

    # Check for rapid connection patterns (potential botnet)
    local connection_frequency=$(netstat -an | grep "$ip" | wc -l)
    if [[ $connection_frequency -gt 15 ]]; then
        echo -e "  ${RED}⚠ High connection frequency: $connection_frequency connections${NC}"
        return 1
    fi

    echo -e "  ${GREEN}✓ No immediate reputation concerns${NC}"
    return 0
}

# Function to assess IP threat level
assess_ip_threat() {
    local ip=$1
    local hostname=$2
    local geo_country=$3
    local geo_region=$4
    local geo_city=$5
    local geo_isp=$6
    local geo_asn=$7
    local threat_level="LOW"
    local threat_reasons=()
    local risk_score=0

    echo -e "${WHITE}Threat Assessment:${NC}"

    # Check for private/local IPs (generally safe)
    if [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^10\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ $ip =~ ^127\. ]]; then
        echo -e "  ${GREEN}✓ Private/Local IP (Safe)${NC}"
        return
    fi

    # Check for link-local
    if [[ $ip =~ ^169\.254\. ]]; then
        threat_level="LOW"
        threat_reasons+=("Link-local address")
        ((risk_score += 1))
    fi

    # Check VPN/Proxy services
    if ! check_vpn_proxy "$ip" "$hostname" "$geo_asn"; then
        threat_level="MEDIUM"
        threat_reasons+=("VPN/Proxy service detected")
        ((risk_score += 3))
    fi

    # Check reputation
    if ! check_ip_reputation "$ip"; then
        threat_level="HIGH"
        threat_reasons+=("Reputation concerns detected")
        ((risk_score += 5))
    fi

    # Check for cloud providers (medium risk)
    if [[ -n "$hostname" ]]; then
        for provider in "${CLOUD_PROVIDERS[@]}"; do
            if echo "$hostname" | grep -qi "$provider"; then
                if [[ "$threat_level" == "LOW" ]]; then
                    threat_level="MEDIUM"
                fi
                threat_reasons+=("Cloud hosting provider: $provider")
                ((risk_score += 2))
                break
            fi
        done
    fi

    # Check for high-risk countries
    if [[ -n "$geo_country" ]]; then
        for country in "${HIGH_RISK_COUNTRIES[@]}"; do
            if [[ "$geo_country" == "$country" ]]; then
                if [[ "$threat_level" == "LOW" ]]; then
                    threat_level="MEDIUM"
                fi
                threat_reasons+=("High-risk geographic location: $country")
                ((risk_score += 2))
                break
            fi
        done
    fi

    # Check for multiple connections
    local port_count=$(netstat -an | grep "$ip" | wc -l)
    if [[ $port_count -gt $MAX_CONNECTIONS_PER_IP ]]; then
        threat_level="MEDIUM"
        threat_reasons+=("Multiple connections ($port_count ports)")
        ((risk_score += 2))
    fi

    # Check for non-standard ports
    local unusual_ports=$(netstat -an | grep "$ip" | awk '{print $5}' | cut -d':' -f2 | sort -u)
    local unusual_count=0
    for port in $unusual_ports; do
        if [[ $port -gt 1024 ]] && [[ $port -lt 65535 ]] && [[ ! " ${SUSPICIOUS_PORTS[@]} " =~ " ${port} " ]]; then
            ((unusual_count++))
        fi
    done

    if [[ $unusual_count -gt 3 ]]; then
        threat_level="MEDIUM"
        threat_reasons+=("Multiple unusual ports ($unusual_count)")
        ((risk_score += 2))
    fi

    # Adjust threat level based on risk score
    if [[ $risk_score -ge 8 ]]; then
        threat_level="HIGH"
    elif [[ $risk_score -ge 4 ]]; then
        threat_level="MEDIUM"
    fi

    # Display threat level with risk score
    case $threat_level in
        "LOW")
            echo -e "  ${GREEN}Threat Level: $threat_level (Risk Score: $risk_score)${NC}"
            ;;
        "MEDIUM")
            echo -e "  ${YELLOW}Threat Level: $threat_level (Risk Score: $risk_score)${NC}"
            ;;
        "HIGH")
            echo -e "  ${RED}Threat Level: $threat_level (Risk Score: $risk_score)${NC}"
            ;;
    esac

    # Display reasons
    if [[ ${#threat_reasons[@]} -gt 0 ]]; then
        echo -e "${WHITE}  Risk Factors:${NC}"
        for reason in "${threat_reasons[@]}"; do
            echo -e "    • $reason"
        done
    fi

    # Log high-risk IPs with detailed info
    if [[ "$threat_level" == "HIGH" ]] || [[ "$threat_level" == "MEDIUM" ]]; then
        log_threat_intelligence "$ip" "$threat_level" "$risk_score" "${threat_reasons[*]}" "$hostname" "$geo_country" "$geo_region" "$geo_city" "$geo_isp" "$geo_asn"
    fi

    # Recommendations based on threat level
    case $threat_level in
        "HIGH")
            echo -e "  ${RED}🚨 RECOMMENDATION: Consider blocking this IP${NC}"
            echo -e "  ${RED}   Monitor closely for malicious activity${NC}"
            ;;
        "MEDIUM")
            echo -e "  ${YELLOW}⚠ RECOMMENDATION: Monitor this connection${NC}"
            echo -e "  ${YELLOW}   Review if connection is necessary${NC}"
            ;;
    esac
}

# Enhanced logging function for threat intelligence
log_threat_intelligence() {
    local ip=$1
    local threat_level=$2
    local risk_score=$3
    local reasons=$4
    local hostname=$5
    local geo_country=$6
    local geo_region=$7
    local geo_city=$8
    local geo_isp=$9
    local geo_asn=${10}
    local intel_log="$HOME/firewall_threat_intel.log"

    # Create detailed intelligence log entry
    {
        echo "========================================"
        echo "TIMESTAMP: $(date)"
        echo "IP_ADDRESS: $ip"
        echo "HOSTNAME: ${hostname:-'Unknown'}"
        echo "THREAT_LEVEL: $threat_level"
        echo "RISK_SCORE: $risk_score"
        echo "RISK_FACTORS: $reasons"
        if [[ -n "$geo_country" ]]; then
            echo "COUNTRY: $geo_country"
            echo "REGION: $geo_region"
            echo "CITY: $geo_city"
            echo "ISP: $geo_isp"
            echo "ASN: $geo_asn"
        fi
        echo "ACTIVE_CONNECTIONS: $(netstat -an | grep "$ip" | wc -l)"
        echo "PORTS_USED: $(netstat -an | grep "$ip" | awk '{print $5}' | cut -d':' -f2 | sort -u | tr '\n' ' ')"
        echo "========================================"
        echo
    } >> "$intel_log"

    # Also log to main log
    log_alert "[$threat_level RISK - Score: $risk_score] $ip ($hostname) - $reasons"
}

# Function to get IP intelligence
get_ip_intelligence() {
    local ip=$1
    local hostname=""
    local geo_country=""
    local geo_region=""
    local geo_city=""
    local geo_isp=""
    local geo_asn=""

    echo -e "${CYAN}🔍 ANALYZING IP: $ip${NC}"
    echo "----------------------------------------"

    # Hostname resolution
    echo -e "${WHITE}Hostname Resolution:${NC}"
    hostname=$(nslookup $ip 2>/dev/null | grep "name =" | awk '{print $4}' | sed 's/\.$//')
    if [[ -n "$hostname" ]]; then
        echo -e "  ${GREEN}Hostname: $hostname${NC}"
    else
        echo -e "  ${YELLOW}No hostname found${NC}"
    fi

    # WHOIS information
    echo -e "${WHITE}WHOIS Information:${NC}"
    if command -v whois >/dev/null 2>&1; then
        local whois_info=$(whois $ip 2>/dev/null | head -20)

        # Extract key information
        local org=$(echo "$whois_info" | grep -i "org\|organization" | head -1 | cut -d':' -f2- | sed 's/^ *//')
        local country=$(echo "$whois_info" | grep -i "country" | head -1 | cut -d':' -f2- | sed 's/^ *//')
        local netname=$(echo "$whois_info" | grep -i "netname\|descr" | head -1 | cut -d':' -f2- | sed 's/^ *//')

        [[ -n "$org" ]] && echo -e "  ${GREEN}Organization: $org${NC}"
        [[ -n "$country" ]] && echo -e "  ${GREEN}Country: $country${NC}"
        [[ -n "$netname" ]] && echo -e "  ${GREEN}Network: $netname${NC}"
    else
        echo -e "  ${YELLOW}whois not available${NC}"
    fi

    # Geolocation (using built-in curl to ip-api if available)
    echo -e "${WHITE}Geolocation:${NC}"
    if command -v curl >/dev/null 2>&1; then
        local geo_info=$(curl -s "http://ip-api.com/line/$ip?fields=country,regionName,city,isp,as" 2>/dev/null)
        if [[ $? -eq 0 ]] && [[ -n "$geo_info" ]]; then
            local geo_array=()
            IFS=$'\n' read -rd '' -a geo_array <<< "$geo_info"

            geo_country="${geo_array[0]}"
            geo_region="${geo_array[1]}"
            geo_city="${geo_array[2]}"
            geo_isp="${geo_array[3]}"
            geo_asn="${geo_array[4]}"

            [[ -n "$geo_country" ]] && echo -e "  ${GREEN}Country: $geo_country${NC}"
            [[ -n "$geo_region" ]] && echo -e "  ${GREEN}Region: $geo_region${NC}"
            [[ -n "$geo_city" ]] && echo -e "  ${GREEN}City: $geo_city${NC}"
            [[ -n "$geo_isp" ]] && echo -e "  ${GREEN}ISP: $geo_isp${NC}"
            [[ -n "$geo_asn" ]] && echo -e "  ${GREEN}ASN: $geo_asn${NC}"
        fi
    fi

    # Threat assessment
    assess_ip_threat "$ip" "$hostname" "$geo_country" "$geo_region" "$geo_city" "$geo_isp" "$geo_asn"

    echo "----------------------------------------"
}

# Function to monitor for suspicious activity
monitor_suspicious() {
    echo -e "${RED}🚨 SECURITY MONITORING${NC}"
    echo "----------------------------------------"

    # Create temporary file for suspicious IPs
    local suspicious_ips_file="/tmp/suspicious_ips_$$"

    # Check for connections to unusual ports
    echo -e "${WHITE}Checking for unusual connections...${NC}"

    # Look for connections to non-standard ports
    netstat -an | grep ESTABLISHED | while read line; do
        remote_ip=$(echo $line | awk '{print $5}' | cut -d':' -f1)
        remote_port=$(echo $line | awk '{print $5}' | cut -d':' -f2)

        # Skip if not a valid IP
        if [[ ! $remote_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            continue
        fi

        if [[ $remote_port =~ ^[0-9]+$ ]] && [[ $remote_port -gt 1024 ]] && [[ $remote_port -lt 65535 ]]; then
            # Check if it's not a common port
            if [[ ! " ${SUSPICIOUS_PORTS[@]} " =~ " ${remote_port} " ]]; then
                echo -e "${YELLOW}Unusual port detected: $line${NC}"
                # Add to suspicious IPs file
                echo "$remote_ip" >> "$suspicious_ips_file"
            fi
        fi
    done

    # Check for too many connections from single IP
    echo -e "${WHITE}Checking for connection flooding...${NC}"
    netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d':' -f1 | sort | uniq -c | sort -nr | head -5 | while read count ip; do
        if [[ $count -gt 10 ]] && [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}High connection count from $ip: $count connections${NC}"
            # Add to suspicious IPs file
            echo "$ip" >> "$suspicious_ips_file"
        fi
    done

    # Analyze suspicious IPs if any found
    if [[ -f "$suspicious_ips_file" ]] && [[ "$ENABLE_IP_ANALYSIS" == "true" ]]; then
        # Get unique IPs
        local unique_ips=$(sort "$suspicious_ips_file" 2>/dev/null | uniq | head -5)

        if [[ -n "$unique_ips" ]]; then
            echo
            echo -e "${RED}🕵️  DETAILED IP INTELLIGENCE ANALYSIS${NC}"
            echo "========================================"

            echo "$unique_ips" | while read ip; do
                if [[ -n "$ip" ]]; then
                    get_ip_intelligence "$ip"
                    echo
                fi
            done
        fi
    fi

    # Cleanup temp file
    [[ -f "$suspicious_ips_file" ]] && rm -f "$suspicious_ips_file"

    echo
}

# Function to show bandwidth usage
show_bandwidth() {
    echo -e "${CYAN}📈 NETWORK BANDWIDTH USAGE${NC}"
    echo "----------------------------------------"

    # Use nettop to show current network usage (run for 2 seconds)
    if command -v nettop >/dev/null 2>&1; then
        echo -e "${WHITE}Top bandwidth consumers (2-second sample):${NC}"
        timeout 2 nettop -p 2>/dev/null | head -10 || echo "nettop data collection..."
    else
        echo -e "${YELLOW}nettop not available for bandwidth monitoring${NC}"
    fi
    echo
}

# Function to log alerts
log_alert() {
    echo "$(date): $1" >> "$LOG_FILE"
}

# Function to show firewall rules (if accessible)
show_firewall_rules() {
    echo -e "${GREEN}🛡️ FIREWALL RULES${NC}"
    echo "----------------------------------------"

    if command -v pfctl >/dev/null 2>&1; then
        echo -e "${WHITE}Packet Filter Rules (first 10):${NC}"
        sudo pfctl -s rules 2>/dev/null | head -10 || echo "Unable to read pfctl rules (may need sudo)"
    fi

    echo
}

# Function to check for port scans
detect_port_scans() {
    echo -e "${RED}🔍 PORT SCAN DETECTION${NC}"
    echo "----------------------------------------"

    # Look for multiple connections from same IP to different ports
    echo -e "${WHITE}Checking for potential port scans...${NC}"
    netstat -an | grep SYN_SENT | awk '{print $5}' | cut -d':' -f1 | sort | uniq -c | sort -nr | head -5 | while read count ip; do
        if [[ $count -gt 5 ]]; then
            echo -e "${RED}Potential port scan detected from $ip: $count outbound SYN attempts${NC}"
            log_alert "Potential port scan from $ip"
        fi
    done
    echo
}

# Function to log ARP security events
log_arp_alert() {
    local message=$1
    local timestamp=$(date)
    echo "$timestamp: $message" >> "$ARP_LOG_FILE"
    log_alert "ARP SECURITY: $message"
}

# Function to initialize ARP monitoring baseline
initialize_arp_baseline() {
    if [[ "$ENABLE_ARP_MONITORING" != "true" ]]; then
        return
    fi

    echo -e "${CYAN}🔍 Initializing ARP baseline...${NC}"

    # Get current ARP table and save as baseline
    arp -a | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" > "$ARP_TABLE_FILE" 2>/dev/null

    # Get and store gateway MAC address
    local gateway_ip=$(netstat -rn | grep default | awk '{print $2}' | head -1)
    if [[ -n "$gateway_ip" ]]; then
        local gateway_mac=$(arp -n "$gateway_ip" 2>/dev/null | awk '{print $4}' | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
        if [[ -n "$gateway_mac" ]]; then
            echo "$gateway_ip $gateway_mac" > "$GATEWAY_MAC_FILE"
            echo -e "${GREEN}✓ Gateway baseline: $gateway_ip -> $gateway_mac${NC}"
        fi
    fi

    # Initialize ARP change tracking
    touch "$ARP_LOG_FILE"
    log_arp_alert "ARP monitoring initialized - baseline established"
}

# Function to detect ARP spoofing attacks
detect_arp_spoofing() {
    if [[ "$ENABLE_ARP_MONITORING" != "true" ]]; then
        return
    fi

    echo -e "${RED}🚨 ARP SPOOF DETECTION${NC}"
    echo "----------------------------------------"

    local current_arp="/tmp/current_arp_$"
    local arp_changes="/tmp/arp_changes_$"
    local suspicious_found=false

    # Get current ARP table
    arp -a | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" > "$current_arp" 2>/dev/null

    echo -e "${WHITE}Checking for ARP table changes...${NC}"

    # Check if baseline exists
    if [[ ! -f "$ARP_TABLE_FILE" ]]; then
        echo -e "${YELLOW}⚠ No ARP baseline found, creating new baseline${NC}"
        cp "$current_arp" "$ARP_TABLE_FILE"
        return
    fi

    # Compare current ARP table with baseline
    local new_entries=$(comm -13 <(sort "$ARP_TABLE_FILE") <(sort "$current_arp") | head -10)
    local removed_entries=$(comm -23 <(sort "$ARP_TABLE_FILE") <(sort "$current_arp") | head -10)

    # Check for new ARP entries
    if [[ -n "$new_entries" ]]; then
        echo -e "${YELLOW}New ARP entries detected:${NC}"
        echo "$new_entries" | while read entry; do
            if [[ -n "$entry" ]]; then
                echo -e "  ${YELLOW}+ $entry${NC}"
                log_arp_alert "New ARP entry: $entry"
            fi
        done
        suspicious_found=true
    fi

    # Check for removed ARP entries
    if [[ -n "$removed_entries" ]]; then
        echo -e "${YELLOW}Removed ARP entries:${NC}"
        echo "$removed_entries" | while read entry; do
            if [[ -n "$entry" ]]; then
                echo -e "  ${YELLOW}- $entry${NC}"
            fi
        done
    fi

    # Check for MAC address conflicts (same IP, different MAC)
    echo -e "${WHITE}Checking for MAC address conflicts...${NC}"
    local conflict_check="/tmp/conflict_check_$"

    # Extract IP and MAC pairs from both baseline and current
    {
        cat "$ARP_TABLE_FILE" 2>/dev/null
        cat "$current_arp" 2>/dev/null
    } | sed 's/.*(\([^)]*\)).* \([0-9a-fA-F:]*\) .*/\1 \2/' | sort > "$conflict_check"

    # Find IPs with multiple MAC addresses
    local conflicts=$(awk '{ip_mac[$1] = ip_mac[$1] " " $2} END {for (ip in ip_mac) if (gsub(/ /, " ", ip_mac[ip]) > 1) print ip, ip_mac[ip]}' "$conflict_check")

    if [[ -n "$conflicts" ]]; then
        echo -e "${RED}🚨 MAC ADDRESS CONFLICTS DETECTED:${NC}"
        echo "$conflicts" | while read ip macs; do
            if [[ -n "$ip" ]]; then
                echo -e "  ${RED}⚠ IP $ip has multiple MAC addresses: $macs${NC}"
                log_arp_alert "MAC CONFLICT: IP $ip has multiple MACs: $macs"
                suspicious_found=true
            fi
        done
    fi

    # Check for rapid MAC changes (potential ARP poisoning)
    echo -e "${WHITE}Checking for rapid MAC changes...${NC}"
    check_rapid_mac_changes "$current_arp"

    # Check gateway integrity
    check_gateway_integrity

    # Check for gratuitous ARP patterns
    check_gratuitous_arp_patterns

    # Update baseline with current state
    cp "$current_arp" "$ARP_TABLE_FILE"

    if [[ "$suspicious_found" == "false" ]]; then
        echo -e "${GREEN}✓ No ARP spoofing detected${NC}"
    fi

    # Cleanup temp files
    rm -f "$current_arp" "$arp_changes" "$conflict_check"

    echo
}

# Function to check for rapid MAC address changes
check_rapid_mac_changes() {
    local current_arp=$1
    local change_log="/tmp/mac_changes_$"

    # Track MAC changes over time (simplified version)
    if [[ -f "$ARP_TABLE_FILE" ]]; then
        # Find IPs where MAC has changed
        while read current_line; do
            if [[ -n "$current_line" ]]; then
                local current_ip=$(echo "$current_line" | sed 's/.*(\([^)]*\)).*/\1/')
                local current_mac=$(echo "$current_line" | grep -oE "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

                # Check if this IP had a different MAC in baseline
                local baseline_mac=$(grep "($current_ip)" "$ARP_TABLE_FILE" 2>/dev/null | grep -oE "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

                if [[ -n "$baseline_mac" ]] && [[ "$current_mac" != "$baseline_mac" ]]; then
                    echo -e "  ${RED}⚠ MAC change detected for $current_ip: $baseline_mac -> $current_mac${NC}"
                    log_arp_alert "MAC CHANGE: $current_ip changed from $baseline_mac to $current_mac"
                fi
            fi
        done < "$current_arp"
    fi
}

# Function to check gateway integrity
check_gateway_integrity() {
    echo -e "${WHITE}Checking gateway integrity...${NC}"

    if [[ ! -f "$GATEWAY_MAC_FILE" ]]; then
        return
    fi

    local stored_gateway=$(cat "$GATEWAY_MAC_FILE" 2>/dev/null)
    local stored_ip=$(echo "$stored_gateway" | awk '{print $1}')
    local stored_mac=$(echo "$stored_gateway" | awk '{print $2}')

    if [[ -n "$stored_ip" ]] && [[ -n "$stored_mac" ]]; then
        local current_mac=$(arp -n "$stored_ip" 2>/dev/null | awk '{print $4}' | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

        if [[ -n "$current_mac" ]]; then
            if [[ "$current_mac" != "$stored_mac" ]]; then
                echo -e "  ${RED}🚨 GATEWAY SPOOFING DETECTED!${NC}"
                echo -e "  ${RED}   Gateway $stored_ip MAC changed: $stored_mac -> $current_mac${NC}"
                echo -e "  ${RED}   This could indicate ARP poisoning attack!${NC}"
                log_arp_alert "CRITICAL: Gateway MAC changed! $stored_ip: $stored_mac -> $current_mac"
            else
                echo -e "  ${GREEN}✓ Gateway MAC verified: $stored_ip -> $stored_mac${NC}"
            fi
        fi
    fi
}

# Function to check for gratuitous ARP patterns
check_gratuitous_arp_patterns() {
    echo -e "${WHITE}Checking for suspicious ARP patterns...${NC}"

    # Check for multiple devices claiming to be the same IP
    local duplicate_ips=$(arp -a | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | \
                         sed 's/.*(\([^)]*\)).*/\1/' | sort | uniq -c | \
                         awk '$1 > 1 {print $1, $2}')

    if [[ -n "$duplicate_ips" ]]; then
        echo -e "${RED}⚠ Multiple entries for same IP detected:${NC}"
        echo "$duplicate_ips" | while read count ip; do
            if [[ -n "$ip" ]]; then
                echo -e "  ${RED}IP $ip appears $count times in ARP table${NC}"
                log_arp_alert "DUPLICATE IP: $ip appears $count times"
            fi
        done
    fi

    # Check for unusual MAC address patterns (common in spoofing tools)
    local suspicious_macs=$(arp -a | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}" | \
                           grep -E "(00:00:00|ff:ff:ff|de:ad:be|ba:ad:f0)" | head -5)

    if [[ -n "$suspicious_macs" ]]; then
        echo -e "${YELLOW}⚠ Suspicious MAC address patterns detected:${NC}"
        echo "$suspicious_macs" | while read entry; do
            if [[ -n "$entry" ]]; then
                echo -e "  ${YELLOW}$entry${NC}"
                log_arp_alert "SUSPICIOUS MAC: $entry"
            fi
        done
    fi
}

# Function to show ARP security status
show_arp_security_status() {
    if [[ "$ENABLE_ARP_MONITORING" != "true" ]]; then
        return
    fi

    echo -e "${CYAN}🛡️ ARP SECURITY STATUS${NC}"
    echo "----------------------------------------"

    # Show current ARP table size
    local arp_count=$(arp -a | grep -c "([0-9]")
    echo -e "${WHITE}Current ARP table entries: $arp_count${NC}"

    # Show gateway status
    if [[ -f "$GATEWAY_MAC_FILE" ]]; then
        local gateway_info=$(cat "$GATEWAY_MAC_FILE" 2>/dev/null)
        echo -e "${WHITE}Protected gateway: $gateway_info${NC}"
    fi

    # Show recent ARP alerts count
    if [[ -f "$ARP_LOG_FILE" ]]; then
        local alert_count=$(grep "$(date +%Y-%m-%d)" "$ARP_LOG_FILE" 2>/dev/null | wc -l)
        if [[ $alert_count -gt 0 ]]; then
            echo -e "${YELLOW}ARP alerts today: $alert_count${NC}"
        else
            echo -e "${GREEN}No ARP alerts today${NC}"
        fi
    fi

    echo
}

# Main monitoring loop
main_loop() {
    while true; do
        print_header
        check_firewall_status
        show_connections
        show_network_processes
        monitor_suspicious
        detect_port_scans
        show_arp_security_status
        detect_arp_spoofing
        show_bandwidth
        show_firewall_rules

        echo -e "${WHITE}Press Ctrl+C to exit...${NC}"
        echo -e "${WHITE}Main Log: ${LOG_FILE}${NC}"
        echo -e "${WHITE}Threat Intel Log: $HOME/firewall_threat_intel.log${NC}"
        if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
            echo -e "${WHITE}ARP Security Log: ${ARP_LOG_FILE}${NC}"
        fi
        if [[ "$ENABLE_IP_ANALYSIS" == "true" ]]; then
            echo -e "${CYAN}🔍 IP Analysis: ENABLED${NC}"
        else
            echo -e "${YELLOW}🔍 IP Analysis: DISABLED${NC}"
        fi
        if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
            echo -e "${CYAN}🛡️ ARP Monitoring: ENABLED${NC}"
        else
            echo -e "${YELLOW}🛡️ ARP Monitoring: DISABLED${NC}"
        fi

        sleep $REFRESH_INTERVAL
    done
}

# Cleanup function
cleanup() {
    echo
    echo -e "${WHITE}Shutting down firewall monitor...${NC}"
    echo "Main log saved to: $LOG_FILE"
    echo "Threat intelligence log: $HOME/firewall_threat_intel.log"
    if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
        echo "ARP security log: $ARP_LOG_FILE"
    fi

    # Clean up temporary files
    rm -f "$ARP_TABLE_FILE" "$GATEWAY_MAC_FILE" 2>/dev/null
    rm -f /tmp/suspicious_ips_$ /tmp/current_arp_$ /tmp/arp_changes_$ /tmp/conflict_check_$ /tmp/mac_changes_$ 2>/dev/null

    echo -e "${GREEN}Stay vigilant! 🛡️${NC}"
    exit 0
}

# Set up signal handling
trap cleanup SIGINT SIGTERM

# Check if running as root for some features
if [[ $EUID -eq 0 ]]; then
    echo -e "${GREEN}Running with root privileges - all features available${NC}"
else
    echo -e "${YELLOW}Running without root - some features may be limited${NC}"
    echo -e "${YELLOW}For full functionality, run: sudo ./firewall_monitor.sh${NC}"
    echo "Press Enter to continue..."
    read
fi

# Display threat intelligence banner
echo -e "${CYAN}🕵️  ENHANCED SECURITY FEATURES ENABLED${NC}"
echo -e "${WHITE}• Hostname resolution for suspicious IPs${NC}"
echo -e "${WHITE}• WHOIS and geolocation lookup${NC}"
echo -e "${WHITE}• VPN/Proxy detection${NC}"
echo -e "${WHITE}• Risk scoring and threat assessment${NC}"
echo -e "${WHITE}• Detailed intelligence logging${NC}"
if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
    echo -e "${WHITE}• ARP spoofing detection and monitoring${NC}"
    echo -e "${WHITE}• Gateway integrity verification${NC}"
    echo -e "${WHITE}• MAC address conflict detection${NC}"
fi
echo -e "${WHITE}• 'Know Thy Enemy' - Sun Tzu would be proud! 🥷${NC}"
echo
echo -e "${YELLOW}Note: External lookups may add slight delay to analysis${NC}"
if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
    echo -e "${YELLOW}ARP monitoring will establish baseline on first run${NC}"
fi
echo "Press Enter to begin monitoring..."
read

# Create log files
touch "$LOG_FILE"
if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
    touch "$ARP_LOG_FILE"
fi
log_alert "Firewall monitor started"

# Initialize ARP monitoring
if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
    initialize_arp_baseline
fi

# Start main loop
main_loop
