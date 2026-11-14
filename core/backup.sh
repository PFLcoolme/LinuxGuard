#!/bin/sh
# core/backup.sh - Configuration backup utilities for LinuxGuard

LG_BACKUP_BASE=''
LG_BACKUP_SESSION=''

# Initialize backup directory
lg_backup_init() {
    if lg_is_root && [ -d /var/backups ]; then
        LG_BACKUP_BASE="/var/backups/linuxguard"
    else
        LG_BACKUP_BASE="/tmp/linuxguard-backups"
    fi

    LG_BACKUP_SESSION=$(date '+%Y%m%d-%H%M%S')-$$
    mkdir -p "${LG_BACKUP_BASE}/${LG_BACKUP_SESSION}"
}

# Backup a single file
# Usage: lg_backup_file /path/to/file
# Returns backup path on stdout, or empty on failure
lg_backup_file() {
    _target=$1
    if [ ! -e "$_target" ]; then
        printf ''
        return 1
    fi

    if [ -z "$LG_BACKUP_BASE" ] || [ -z "$LG_BACKUP_SESSION" ]; then
        lg_backup_init
    fi

    _backup_dir="${LG_BACKUP_BASE}/${LG_BACKUP_SESSION}"
    _backup_path="${_backup_dir}/$(printf '%s' "$_target" | tr '/' '_').bak"

    if cp -p "$_target" "$_backup_path" 2>/dev/null; then
        lg_log "BACKUP" "$_target" "$_backup_path"
        printf '%s' "$_backup_path"
        return 0
    else
        lg_log "BACKUP_FAILED" "$_target" "$_backup_path"
        printf ''
        return 1
    fi
}

# List backups in current session
lg_backup_list() {
    if [ -z "$LG_BACKUP_BASE" ] || [ -z "$LG_BACKUP_SESSION" ]; then
        return 1
    fi
    ls -1 "${LG_BACKUP_BASE}/${LG_BACKUP_SESSION}" 2>/dev/null
}

# Get backup path for a target file in current session
lg_backup_path_for() {
    _target=$1
    printf '%s/%s/%s.bak' "$LG_BACKUP_BASE" "$LG_BACKUP_SESSION" "$(printf '%s' "$_target" | tr '/' '_')"
}

# Cleanup backups for current session
lg_backup_cleanup() {
    if [ -n "$LG_BACKUP_BASE" ] && [ -n "$LG_BACKUP_SESSION" ]; then
        rm -rf "${LG_BACKUP_BASE}/${LG_BACKUP_SESSION}"
    fi
}
