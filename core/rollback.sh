#!/bin/sh
# core/rollback.sh - Configuration rollback utilities for LinuxGuard

# Restore a file from its backup
# Usage: lg_rollback_file /path/to/original /path/to/backup
lg_rollback_file() {
    _target=$1
    _backup=$2

    if [ ! -f "$_backup" ]; then
        lg_log "ROLLBACK_FAILED" "$_target" "backup missing: $_backup"
        return 1
    fi

    if cp -p "$_backup" "$_target" 2>/dev/null; then
        lg_log "ROLLBACK" "$_target" "$_backup"
        return 0
    else
        lg_log "ROLLBACK_FAILED" "$_target" "copy failed"
        return 1
    fi
}

# Rollback all files backed up in the current session
lg_rollback_session() {
    _count=0
    _failed=0

    if [ -z "$LG_BACKUP_BASE" ] || [ -z "$LG_BACKUP_SESSION" ]; then
        printf 'No active backup session to rollback.\n'
        return 1
    fi

    _session_dir="${LG_BACKUP_BASE}/${LG_BACKUP_SESSION}"
    if [ ! -d "$_session_dir" ]; then
        printf 'Backup session directory not found: %s\n' "$_session_dir"
        return 1
    fi

    for _backup in "$_session_dir"/*.bak; do
        if [ ! -f "$_backup" ]; then
            continue
        fi
        _count=$((_count + 1))
        # Derive original path from backup filename
        _orig=$(basename "$_backup" .bak | tr '_' '/')
        if lg_rollback_file "$_orig" "$_backup"; then
            : # success
        else
            _failed=$((_failed + 1))
        fi
    done

    if [ "$_failed" -eq 0 ]; then
        lg_log "ROLLBACK_SESSION" "$_session_dir" "restored $_count file(s)"
        printf 'Rolled back %d file(s).\n' "$_count"
        return 0
    else
        lg_log "ROLLBACK_SESSION_FAILED" "$_session_dir" "$_failed failed"
        printf 'Rollback completed with %d failure(s).\n' "$_failed"
        return 1
    fi
}
