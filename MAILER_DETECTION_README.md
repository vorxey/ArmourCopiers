# macOS Hacker Mailer Detection Tool

A comprehensive security script designed to detect potential malicious mailers, spam bots, and brute-force activities on macOS systems.

## Overview

This tool scans your macOS system for indicators of compromise related to malicious email sending activities, including:
- Suspicious mail-related processes
- Known malicious mailer scripts
- Brute-force authentication attempts
- Unauthorized network connections on mail ports
- Modified mail server configurations
- Persistence mechanisms
- Obfuscated scripts

## Features

1. **Process Monitoring**: Detects suspicious mail-related processes running on the system
2. **File System Scanning**: Searches common locations for malicious mailer scripts
3. **Log Analysis**: Checks mail logs for brute-force attempts and authentication failures
4. **Network Analysis**: Monitors active connections on SMTP and mail-related ports
5. **Configuration Auditing**: Examines Postfix/Sendmail configurations for open relay issues
6. **Persistence Detection**: Scans LaunchAgents and LaunchDaemons for mail-related persistence
7. **Web Server Scanning**: Identifies PHP mailer scripts in web directories
8. **Cron Job Analysis**: Reviews scheduled tasks for suspicious mail activities
9. **Obfuscation Detection**: Finds base64-encoded or obfuscated scripts
10. **Recent File Monitoring**: Tracks recently modified suspicious files

## Requirements

- macOS 10.13 or later
- Bash shell (pre-installed on macOS)
- Root/sudo access (recommended for full scanning capabilities)

## Installation

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/yourrepo/macos_mailer_detector.sh
```

Or clone the repository:
```bash
git clone https://github.com/yourrepo/ArmourCopiers.git
cd ArmourCopiers
```

2. Make the script executable:
```bash
chmod +x macos_mailer_detector.sh
```

## Usage

### Basic Scan (Limited Permissions)
```bash
./macos_mailer_detector.sh
```

### Full Scan (Recommended - Requires Root)
```bash
sudo ./macos_mailer_detector.sh
```

## Output Interpretation

The script uses color-coded output:
- **RED (THREAT)**: Critical security issues requiring immediate attention
- **YELLOW (WARNING)**: Suspicious activities that should be investigated
- **GREEN**: No threats detected
- **BLUE**: Informational messages

### Exit Codes
- `0`: No threats or warnings found
- `1`: Warnings detected
- `2`: Threats detected

## What to Do If Threats Are Found

1. **Review the Log File**: Check the detailed log saved in `/tmp/mailer_detection_YYYYMMDD_HHMMSS.log`

2. **Investigate Suspicious Processes**:
   ```bash
   # View process details
   ps aux | grep <process_name>

   # Terminate suspicious process
   sudo kill -9 <PID>
   ```

3. **Examine Suspicious Files**:
   ```bash
   # View file contents
   cat <suspicious_file_path>

   # Check file permissions and ownership
   ls -la <suspicious_file_path>

   # Remove if confirmed malicious
   sudo rm <suspicious_file_path>
   ```

4. **Check Network Connections**:
   ```bash
   # View all network connections
   sudo lsof -i -P

   # Block suspicious IP addresses
   sudo pfctl -t blocklist -T add <IP_ADDRESS>
   ```

5. **Review System Logs**:
   ```bash
   # Check system logs
   log show --predicate 'eventMessage contains "mail"' --last 1d

   # Check authentication logs
   log show --predicate 'process == "loginwindow"' --last 1d
   ```

6. **Disable Suspicious Launch Items**:
   ```bash
   # Unload suspicious LaunchAgent/Daemon
   sudo launchctl unload <path_to_plist>

   # Remove the plist file
   sudo rm <path_to_plist>
   ```

7. **Secure Your System**:
   - Change all passwords
   - Update macOS and all applications
   - Enable FileVault encryption
   - Enable Firewall in System Preferences
   - Install and run antivirus software

## Common False Positives

The following are typically legitimate and can be ignored:
- Apple Mail processes (com.apple.mail)
- Microsoft Outlook processes
- Thunderbird mail client
- Legitimate PHP applications with mail functionality
- Authorized cron jobs for system notifications

## Advanced Usage

### Schedule Regular Scans

Create a cron job to run daily scans:
```bash
# Edit crontab
crontab -e

# Add this line to run daily at 2 AM
0 2 * * * /path/to/macos_mailer_detector.sh >> /var/log/mailer_scan.log 2>&1
```

### Custom Scanning

Modify the script variables to customize scanning:
- `SCAN_PATHS`: Add or remove directories to scan
- `SUSPICIOUS_PROCESSES`: Add known malicious process names
- `MAIL_PORTS`: Add custom mail ports to monitor

## Detected Threat Categories

### 1. Malicious Mailer Scripts
- PHPMailer exploits
- Mass mailing scripts
- Spam bots
- Anonymous mailers

### 2. Brute Force Indicators
- Multiple authentication failures
- Rapid connection attempts
- Dictionary attacks on mail services

### 3. Configuration Exploits
- Open relay configurations
- Unauthorized relay domains
- Modified sendmail/postfix settings

### 4. Persistence Mechanisms
- Malicious LaunchAgents
- Suspicious LaunchDaemons
- Hidden cron jobs

### 5. Obfuscated Threats
- Base64-encoded payloads
- Eval-based execution
- Hidden backdoors

## Limitations

- Cannot detect all zero-day threats
- May produce false positives with legitimate mail services
- Requires root access for comprehensive scanning
- Does not remove threats automatically (manual intervention required)

## Security Considerations

- This script performs READ-ONLY operations (does not modify system)
- Logs may contain sensitive information - handle securely
- Run from a trusted source only
- Review script contents before execution with sudo

## Troubleshooting

### Permission Denied Errors
Run with sudo for full access:
```bash
sudo ./macos_mailer_detector.sh
```

### Script Won't Execute
Ensure executable permissions:
```bash
chmod +x macos_mailer_detector.sh
```

### No Output
Check if script is compatible with your shell:
```bash
bash ./macos_mailer_detector.sh
```

## Contributing

Contributions are welcome! Please submit pull requests or report issues on GitHub.

## License

This tool is provided as-is for defensive security purposes only. Use responsibly and in compliance with applicable laws.

## Disclaimer

This tool is for authorized security testing and defensive purposes only. Users are responsible for ensuring they have proper authorization before scanning systems. The authors are not responsible for misuse or damage caused by this tool.

## Support

For issues, questions, or contributions, please visit the GitHub repository or contact the maintainers.

## Version History

- **v1.0.0** (2025-11-11): Initial release
  - Process monitoring
  - File system scanning
  - Log analysis
  - Network monitoring
  - Configuration auditing
  - Persistence detection
