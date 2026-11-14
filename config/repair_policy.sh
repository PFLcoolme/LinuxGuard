#!/bin/sh
# config/repair_policy.sh - Repair policy mapping for LinuxGuard
#
# Format per line: RULE_ID=REPAIR_FUNCTION:LEVEL
# Levels: L1 (auto), L2 (confirm default yes), L3 (confirm), L4 (strict confirm)

LG_REPAIR_POLICY='
SSH_ROOT_LOGIN=lg_repair_ssh_root_login:L3
SSH_PASSWORD_AUTH=lg_repair_ssh_password_auth:L3
SSH_EMPTY_PASSWORD=lg_repair_ssh_empty_password:L2
SSH_LISTEN_ADDRESS=lg_repair_ssh_listen_address:L3
UID0_EXTRA_USERS=lg_repair_uid0_users:L4
EMPTY_PASSWORDS=lg_repair_empty_passwords:L2
UNUSUAL_SHELL=lg_repair_unusual_shell:L3
STALE_PASSWORDS=lg_repair_stale_passwords:L1
SUDO_NOPASSWD=lg_repair_sudo_nopasswd:L3
SUDO_ALL_ALL=lg_repair_sudo_all_all:L3
SUDO_RISKY_PATTERN=lg_repair_sudo_risky:L3
SUDOERS_PERMISSIONS=lg_repair_sudoers_permissions:L2
FIREWALL_STATUS=lg_repair_firewall_status:L3
KERNEL_ASLR=lg_repair_kernel_aslr:L2
KERNEL_KPTR_RESTRICT=lg_repair_kernel_kptr_restrict:L2
KERNEL_MODULES_DISABLED=lg_repair_kernel_modules_disabled:L2
KERNEL_IP_FORWARD=lg_repair_kernel_ip_forward:L3
KERNEL_RP_FILTER=lg_repair_kernel_rp_filter:L2
PERM_PASSWD=lg_repair_perm_passwd:L2
PERM_GROUP=lg_repair_perm_group:L2
PERM_SHADOW=lg_repair_perm_shadow:L2
PERM_SSH_HOST_KEYS=lg_repair_perm_ssh_host_keys:L2
#
# Threat-detection modules (processes / malware / vulnscan) intentionally have
# NO entries here: they are read-only indicators that require human judgment,
# so they are never auto-repaired. They appear under "Manual / 需手工" in the
# repair feasibility statistics. See docs/SECURITY.md.
#
# The V1.2 hardening modules (netstack / filesystem / auth / audit / services)
# follow the same rule: read-only checks with NO repair entries, always manual.
DOCKER_SOCKET=lg_repair_docker_socket:L2
'

# Get repair function for a rule
lg_policy_get_function() {
    _rule=$1
    printf '%s' "$LG_REPAIR_POLICY" | grep -E "^${_rule}=" | head -n 1 | cut -d'=' -f2 | cut -d':' -f1
}

# Get repair level for a rule
lg_policy_get_level() {
    _rule=$1
    printf '%s' "$LG_REPAIR_POLICY" | grep -E "^${_rule}=" | head -n 1 | cut -d':' -f2 | tr -d '[:space:]'
}
