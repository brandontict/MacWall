<p>&nbsp;</p>
<p style="text-align: left;"># Real-time Firewall Monitor for macOS<br /># Uses built-in tools: netstat, lsof, pfctl, nettop</br></p>
<h1><strong>MacWall - Realtime 🔥Firewall🧱&nbsp;</strong></h1>
<p>This project is in beta. I was looking for a firewall for my Mac Pro . Alot great ones out there, Although&nbsp; I rather be in the terminal if possible. Claude and I turned out this Real Time Firewall that does not ( should not ) need any pre&nbsp;prerequisites.</p>
<p>Some features , such as real time Risk scoring and threat assessment and Detailed intelligence logging via Mac OSx and Linux terminal.</p>
<p>&nbsp;</p>
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

<h3> Screenshots</h3>
<img width="423" height="225" alt="image" src="https://github.com/user-attachments/assets/c5f9b804-cfef-487a-9704-27cec73726df" />
<img width="472" height="352" alt="image" src="https://github.com/user-attachments/assets/b49f135b-a154-4a68-bf03-4558cbaa2962" />
<img width="633" height="785" alt="image" src="https://github.com/user-attachments/assets/bad635f3-5701-4ed3-a2eb-ff4e23655cd4" />
<img width="450" height="321" alt="image" src="https://github.com/user-attachments/assets/5cc8a759-9e7f-4564-acc5-719fc0fe9109" />

<p><strong>This is collab with Cladue :-D I wish I could take FULL credit , But I cannot . </strong></p>
