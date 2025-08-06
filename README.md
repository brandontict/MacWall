<p>&nbsp;</p>
<p style="text-align: left;"># Real-time Firewall Monitor for macOS<br /># Uses built-in tools: netstat, lsof, pfctl, nettop</br></p>
<h1><strong>MacWall - Realtime 🔥Firewall🧱&nbsp;</strong></h1>
<p>This project is in beta. I was looking for a firewall for my Mac Pro . Alot great ones out there, Although&nbsp; I rather be in the terminal if possible. Claude and I turned out this Real Time Firewall that does not ( should not ) need any pre&nbsp;prerequisites.</p>
<p>Some features , such as real time Risk scoring and threat assessment and Detailed intelligence logging via Mac OSx and Linux terminal.</p>
<p>&nbsp;</p>
<h3> Screenshots</h3>


<p><strong>This is collab with Cladue :-D I wish I could take FULL credit , But I cannot . </strong></p>
<h3>** Recent updates ** </h3>

<b>Macwall monitoring script with a comprehensive file integrity checking system! Here are the key additions:</b>

🌐 Network Security (original functionality)
🛡️ ARP Spoofing Protection
🔒 File System Integrity (new addition)

Usage: The script will automatically create baselines on first run and begin monitoring. Any tampering with critical files will be immediately detected and logged with detailed change information! Run with: sudo chmod +x Macwall.sh &amp;&amp; ./Macwall.sh . 


🔒 New File Integrity Features Added:

Configuration Variables

ENABLE_FILE_INTEGRITY=true - Master switch for file integrity monitoring
INTEGRITY_CHECK_INTERVAL=5 - Checks files every N monitoring cycles (reduces overhead)
Dedicated log file: $HOME/file_integrity.log
Baseline storage directory: $HOME/.macwall_baselines

Critical Files Being Monitored
System Security Files:

/etc/passwd, /etc/sudoers, /etc/hosts
/etc/ssh/sshd_config, /etc/ssh/ssh_config
/etc/shells, /etc/resolv.conf
System launch daemons and authorization files

User-Specific Files:

~/.ssh/authorized_keys, ~/.ssh/config
Shell profiles (.bashrc, .zshrc, .profile)

Application Credentials:

~/.aws/credentials, ~/.docker/config.json
~/.netrc and other credential files

<h2>Detection Capabilities</h2>
<p>
✅ MD5 Checksum Verification - Detects content tampering

  ✅ Modification Time Tracking - Identifies when files changed

✅ Permission/Ownership Changes - Detects privilege escalation

✅ File Deletion Detection - Alerts when critical files disappear

✅ Recent Activity Monitoring - Finds suspicious recent changes

✅ Risk-Based Alerting - HIGH risk for auth files, MEDIUM for others
</p>
<h2>Key Functions Added</h2>

initialize_file_integrity() - Creates baseline checksums on first run

check_file_integrity() - Compares current state vs baseline

detect_suspicious_modifications() - Finds recently changed critical files

show_file_integrity_status() - Displays monitoring status

<h2>Smart Features</h2>

Baseline Auto-Update: Non-critical files get updated baselines automatically

Critical File Protection: Security files (passwd, sudoers, SSH keys) require manual investigation

Performance Optimized: Only checks files every N cycles to reduce system load

Comprehensive Logging: Detailed violation logs with timestamps and change details


