#!/bin/sh
# config/rules.sh - Detection rules and thresholds for LinuxGuard

# SSH configuration files and common paths
LG_SSHD_CONFIG='/etc/ssh/sshd_config'
LG_SSHD_CONFIG_D='/etc/ssh/sshd_config.d'

# Password age threshold (days) for stale password warning
LG_PASSWORD_AGE_DAYS=180

# Shells considered invalid/login-disabled
LG_INVALID_SHELLS='/bin/false /usr/bin/false /bin/nologin /usr/bin/nologin /sbin/nologin /usr/sbin/nologin'

# Ports considered high-risk when listening publicly
LG_HIGH_RISK_TCP_PORTS='21 23 25 110 143 3306 3389 5432 5900 6379 8080 8443 9200'

# Common services considered high-risk when exposed
LG_HIGH_RISK_SERVICES='telnet ftp rsh rexec rlogin ssh mysql postgres redis vnc x11'

# UFW expected default policy when enabled
LG_UFW_DEFAULT_DENY=1

# High-risk sudoers patterns (space-separated globs for grep)
LG_SUDO_RISKY_PATTERNS='NOPASSWD ALL=(ALL) ALL=(ALL:ALL) !authenticate'

# Whitelist of system accounts allowed to have UID 0 beyond root
LG_UID0_WHITELIST='root'

# --- Threat detection modules / 威胁检测模块 -------------------------------

# Suspicious process indicators (space-separated; matched case-insensitively)
# NOTE: use single tokens without spaces; "bash -i" style phrases are not used
# because the matcher is token based.
LG_PROC_SUSPICIOUS_NAMES='xmrig minerd cpuminer ethminer cgminer kworkerds kthreaddds sysupdate networkservice cryptominer'
LG_PROC_MINER_KEYWORDS='stratum+tcp cryptonight monero xmr.pool donate-level coinhive'

# Malware / rootkit indicator settings
LG_MALWARE_TMP_DIRS='/tmp /var/tmp /dev/shm'
LG_MALWARE_SCAN_AGE_DAYS=30

# Vulnerability posture settings
LG_VULNSCAN_UPGRADE_THRESHOLD=10
LG_VULNSCAN_REBOOT_MARKERS='/var/run/reboot-required /run/reboot-required'

# --- V1.2 hardening modules / V1.2 加固模块 -------------------------------

# Authentication policy thresholds (auth.sh)
LG_AUTH_PASS_MAX_DAYS=90
LG_AUTH_PASS_MIN_LEN=8

# Filesystem module: shared temp directories checked for the sticky bit
LG_FS_SHARED_TMP_DIRS='/tmp /var/tmp /dev/shm'

# Services module: startup directories checked for permissive modes
LG_SVC_STARTUP_DIRS='/etc/init.d /etc/rc.d /etc/cron.d /etc/systemd/system'
