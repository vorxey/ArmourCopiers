#!/bin/bash

################################################################################
# macOS Hacker Mailer Detection Script
# Purpose: Detect potential malicious mailers and brute-force activities
# Compatible with: macOS 10.13+
################################################################################

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detection results
THREATS_FOUND=0
WARNINGS_FOUND=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}macOS Hacker Mailer Detection Tool${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo -e "${RED}[ERROR] This script is designed for macOS only${NC}"
    exit 1
fi

# Check if running with sudo (needed for some checks)
if [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}[WARNING] Script not running as root. Some checks may be limited.${NC}"
   echo -e "${YELLOW}For full scanning, run: sudo $0${NC}"
   echo ""
fi

# Create temporary log file
TEMP_LOG="/tmp/mailer_detection_$(date +%Y%m%d_%H%M%S).log"
echo "Scan started: $(date)" > "$TEMP_LOG"

################################################################################
# 1. Check for Suspicious Mail Processes
################################################################################
echo -e "${BLUE}[*] Checking for suspicious mail-related processes...${NC}"

# Known malicious or suspicious mailer process names
SUSPICIOUS_PROCESSES=(
    "phpmailer"
    "sendmail.pl"
    "mass_mailer"
    "bulk_sender"
    "smtp_sender"
    "mail_bomber"
    "anonymous_mailer"
    "stealth_mail"
    "perl.*mail"
    "python.*smtp"
    "python.*mailer"
    "ruby.*mailer"
    "node.*mailer"
    "nc.*25"  # netcat on SMTP port
    "telnet.*25"
    "openssl.*s_client.*25"
)

for proc in "${SUSPICIOUS_PROCESSES[@]}"; do
    if pgrep -fil "$proc" > /dev/null 2>&1; then
        PROCESSES=$(pgrep -fil "$proc")
        echo -e "${RED}[THREAT] Suspicious process detected: $proc${NC}"
        echo "$PROCESSES"
        echo "[THREAT] Process: $proc - $PROCESSES" >> "$TEMP_LOG"
        ((THREATS_FOUND++))
    fi
done

################################################################################
# 2. Check for Known Malicious Mailer Scripts
################################################################################
echo -e "${BLUE}[*] Scanning for known malicious mailer scripts...${NC}"

# Common locations where malicious scripts might hide
SCAN_PATHS=(
    "/tmp"
    "/var/tmp"
    "/Users/*/Downloads"
    "/Users/*/Documents"
    "/Users/*/Library/LaunchAgents"
    "/Library/LaunchDaemons"
    "/Library/LaunchAgents"
    "/usr/local/bin"
    "/opt"
)

# Suspicious script patterns
SCRIPT_PATTERNS=(
    "*mass*mail*"
    "*bulk*mail*"
    "*spam*"
    "*smtp*brute*"
    "*mail*bomb*"
    "*anonymous*mail*"
    "c99.php"
    "r57.php"
    "wso.php"
    "*shell*.php"
    "*mailer*.php"
)

for path in "${SCAN_PATHS[@]}"; do
    if [[ -d "$path" ]]; then
        for pattern in "${SCRIPT_PATTERNS[@]}"; do
            while IFS= read -r -d '' file; do
                if [[ -f "$file" ]]; then
                    echo -e "${RED}[THREAT] Suspicious file found: $file${NC}"
                    echo "[THREAT] File: $file" >> "$TEMP_LOG"
                    ((THREATS_FOUND++))
                fi
            done < <(find "$path" -maxdepth 2 -iname "$pattern" -print0 2>/dev/null)
        done
    fi
done

################################################################################
# 3. Check for Brute Force Attempts in Mail Logs
################################################################################
echo -e "${BLUE}[*] Checking for brute-force attempts in mail logs...${NC}"

MAIL_LOGS=(
    "/var/log/mail.log"
    "/var/log/system.log"
    "/private/var/log/mail.log"
)

for log in "${MAIL_LOGS[@]}"; do
    if [[ -f "$log" ]]; then
        # Check for authentication failures
        FAILED_AUTH=$(grep -i "authentication failed\|failed login\|invalid user" "$log" 2>/dev/null | wc -l)
        if [[ $FAILED_AUTH -gt 50 ]]; then
            echo -e "${YELLOW}[WARNING] Multiple authentication failures detected in $log: $FAILED_AUTH occurrences${NC}"
            echo "[WARNING] Auth failures in $log: $FAILED_AUTH" >> "$TEMP_LOG"
            ((WARNINGS_FOUND++))
        fi

        # Check for rapid connection attempts
        RAPID_CONNECTIONS=$(grep -i "connection from\|connect from" "$log" 2>/dev/null | tail -100 | wc -l)
        if [[ $RAPID_CONNECTIONS -gt 50 ]]; then
            echo -e "${YELLOW}[WARNING] Rapid connection attempts detected in $log: $RAPID_CONNECTIONS recent connections${NC}"
            echo "[WARNING] Rapid connections in $log: $RAPID_CONNECTIONS" >> "$TEMP_LOG"
            ((WARNINGS_FOUND++))
        fi
    fi
done

################################################################################
# 4. Check Network Connections on Mail Ports
################################################################################
echo -e "${BLUE}[*] Checking for suspicious network connections on mail ports...${NC}"

MAIL_PORTS=(25 587 465 2525)

for port in "${MAIL_PORTS[@]}"; do
    CONNECTIONS=$(lsof -i ":$port" -n -P 2>/dev/null)
    if [[ -n "$CONNECTIONS" ]]; then
        echo -e "${YELLOW}[WARNING] Active connections on mail port $port:${NC}"
        echo "$CONNECTIONS"
        echo "[WARNING] Connections on port $port: $CONNECTIONS" >> "$TEMP_LOG"
        ((WARNINGS_FOUND++))
    fi
done

# Check for unusual outbound SMTP connections
OUTBOUND_SMTP=$(lsof -i TCP -s TCP:ESTABLISHED -n -P 2>/dev/null | grep ":25\|:587\|:465" | grep -v "Mail\|Outlook\|Thunderbird")
if [[ -n "$OUTBOUND_SMTP" ]]; then
    echo -e "${RED}[THREAT] Suspicious outbound SMTP connections detected:${NC}"
    echo "$OUTBOUND_SMTP"
    echo "[THREAT] Outbound SMTP: $OUTBOUND_SMTP" >> "$TEMP_LOG"
    ((THREATS_FOUND++))
fi

################################################################################
# 5. Check for Modified Postfix/Sendmail Configurations
################################################################################
echo -e "${BLUE}[*] Checking mail server configurations...${NC}"

POSTFIX_CONFIG="/etc/postfix/main.cf"
SENDMAIL_CONFIG="/etc/mail/sendmail.cf"

if [[ -f "$POSTFIX_CONFIG" ]]; then
    # Check for suspicious relay configurations
    if grep -q "^relay_domains.*=.*" "$POSTFIX_CONFIG" 2>/dev/null; then
        RELAY_DOMAINS=$(grep "^relay_domains" "$POSTFIX_CONFIG")
        echo -e "${YELLOW}[WARNING] Relay domains configured in Postfix:${NC}"
        echo "$RELAY_DOMAINS"
        echo "[WARNING] Postfix relay: $RELAY_DOMAINS" >> "$TEMP_LOG"
        ((WARNINGS_FOUND++))
    fi

    # Check for open relay configuration
    if grep -q "^mynetworks.*=.*0\.0\.0\.0" "$POSTFIX_CONFIG" 2>/dev/null; then
        echo -e "${RED}[THREAT] Postfix configured as OPEN RELAY!${NC}"
        echo "[THREAT] Postfix open relay detected" >> "$TEMP_LOG"
        ((THREATS_FOUND++))
    fi
fi

################################################################################
# 6. Check LaunchAgents and LaunchDaemons for Persistence
################################################################################
echo -e "${BLUE}[*] Checking for persistence mechanisms...${NC}"

LAUNCH_PATHS=(
    "/Library/LaunchDaemons"
    "/Library/LaunchAgents"
    "/Users/*/Library/LaunchAgents"
)

for lpath in "${LAUNCH_PATHS[@]}"; do
    while IFS= read -r -d '' plist; do
        # Check for mail-related launch agents
        if grep -q -i "mail\|smtp\|sendmail\|postfix" "$plist" 2>/dev/null; then
            # Exclude legitimate mail services
            if ! grep -q "com.apple.mail\|com.microsoft.Outlook" "$plist" 2>/dev/null; then
                echo -e "${YELLOW}[WARNING] Mail-related launch item: $plist${NC}"
                echo "[WARNING] Launch item: $plist" >> "$TEMP_LOG"
                ((WARNINGS_FOUND++))
            fi
        fi
    done < <(find "$lpath" -name "*.plist" -print0 2>/dev/null)
done

################################################################################
# 7. Check for PHP Mail Functions in Web Directories
################################################################################
echo -e "${BLUE}[*] Scanning for PHP mail scripts in web directories...${NC}"

WEB_DIRS=(
    "/Library/WebServer/Documents"
    "/Users/*/Sites"
    "/Applications/MAMP/htdocs"
    "/Applications/XAMPP/htdocs"
)

for webdir in "${WEB_DIRS[@]}"; do
    if [[ -d "$webdir" ]]; then
        # Look for PHP files with mail functions
        PHP_MAILERS=$(grep -r -l "mail\s*(" "$webdir" --include="*.php" 2>/dev/null)
        if [[ -n "$PHP_MAILERS" ]]; then
            echo -e "${YELLOW}[WARNING] PHP files with mail() function in $webdir:${NC}"
            echo "$PHP_MAILERS"
            echo "[WARNING] PHP mailers in $webdir: $PHP_MAILERS" >> "$TEMP_LOG"
            ((WARNINGS_FOUND++))
        fi
    fi
done

################################################################################
# 8. Check for Suspicious Cron Jobs
################################################################################
echo -e "${BLUE}[*] Checking cron jobs for mail-related tasks...${NC}"

# Check system crontab
if [[ -f "/etc/crontab" ]]; then
    CRON_MAIL=$(grep -i "mail\|smtp\|sendmail" /etc/crontab 2>/dev/null)
    if [[ -n "$CRON_MAIL" ]]; then
        echo -e "${YELLOW}[WARNING] Mail-related cron jobs in system crontab:${NC}"
        echo "$CRON_MAIL"
        echo "[WARNING] System cron: $CRON_MAIL" >> "$TEMP_LOG"
        ((WARNINGS_FOUND++))
    fi
fi

# Check user crontabs
for user in $(dscl . -list /Users | grep -v "^_"); do
    CRON_OUTPUT=$(crontab -u "$user" -l 2>/dev/null | grep -i "mail\|smtp\|sendmail")
    if [[ -n "$CRON_OUTPUT" ]]; then
        echo -e "${YELLOW}[WARNING] Mail-related cron job for user $user:${NC}"
        echo "$CRON_OUTPUT"
        echo "[WARNING] User cron ($user): $CRON_OUTPUT" >> "$TEMP_LOG"
        ((WARNINGS_FOUND++))
    fi
done

################################################################################
# 9. Check for Base64 Encoded Scripts (Common Obfuscation)
################################################################################
echo -e "${BLUE}[*] Scanning for potentially obfuscated mailer scripts...${NC}"

OBFUSCATED=$(find /tmp /var/tmp -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | \
    xargs grep -l "base64.*decode\|eval.*base64\|exec.*base64" 2>/dev/null)

if [[ -n "$OBFUSCATED" ]]; then
    echo -e "${RED}[THREAT] Potentially obfuscated scripts found:${NC}"
    echo "$OBFUSCATED"
    echo "[THREAT] Obfuscated scripts: $OBFUSCATED" >> "$TEMP_LOG"
    ((THREATS_FOUND++))
fi

################################################################################
# 10. Check Recent File Modifications in Suspicious Locations
################################################################################
echo -e "${BLUE}[*] Checking for recently modified files in sensitive locations...${NC}"

RECENT_FILES=$(find /tmp /var/tmp -type f -mtime -1 \( -name "*.php" -o -name "*.pl" -o -name "*.py" -o -name "*.sh" \) 2>/dev/null)

if [[ -n "$RECENT_FILES" ]]; then
    echo -e "${YELLOW}[WARNING] Recently modified scripts in temporary directories:${NC}"
    echo "$RECENT_FILES"
    echo "[WARNING] Recent files: $RECENT_FILES" >> "$TEMP_LOG"
    ((WARNINGS_FOUND++))
fi

################################################################################
# Summary Report
################################################################################
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Scan Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Threats Found: ${RED}$THREATS_FOUND${NC}"
echo -e "Warnings Found: ${YELLOW}$WARNINGS_FOUND${NC}"
echo ""

if [[ $THREATS_FOUND -eq 0 && $WARNINGS_FOUND -eq 0 ]]; then
    echo -e "${GREEN}[✓] No immediate threats or warnings detected${NC}"
else
    echo -e "${YELLOW}Full scan log saved to: $TEMP_LOG${NC}"
    echo ""
    echo -e "${BLUE}Recommended Actions:${NC}"
    echo "1. Review all detected threats and warnings"
    echo "2. Investigate unfamiliar processes and files"
    echo "3. Check system logs for unauthorized access"
    echo "4. Update and run antivirus software"
    echo "5. Consider resetting passwords if compromise is suspected"
    echo "6. Review firewall rules and network connections"
fi

echo ""
echo "Scan completed: $(date)" >> "$TEMP_LOG"
echo -e "${BLUE}========================================${NC}"

# Exit with appropriate code
if [[ $THREATS_FOUND -gt 0 ]]; then
    exit 2
elif [[ $WARNINGS_FOUND -gt 0 ]]; then
    exit 1
else
    exit 0
fi
