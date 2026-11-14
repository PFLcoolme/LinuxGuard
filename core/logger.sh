#!/bin/sh
# core/logger.sh - Operation logging for LinuxGuard

LG_LOG_FILE=''

# Initialize log file
lg_log_init() {
    if lg_is_root && [ -d /var/log ]; then
        LG_LOG_FILE='/var/log/linuxguard.log'
    else
        LG_LOG_FILE="/tmp/linuxguard-$$.log"
    fi

    if [ ! -f "$LG_LOG_FILE" ]; then
        touch "$LG_LOG_FILE" 2>/dev/null || true
    fi
}

# Log an event
# Usage: lg_log ACTION TARGET DETAILS
lg_log() {
    _action=$1
    _target=$2
    _details=$3

    if [ -z "$LG_LOG_FILE" ]; then
        lg_log_init
    fi

    printf '%s [%s] target="%s" details="%s"\n' \
        "$(lg_timestamp)" "$_action" "$_target" "$_details" >> "$LG_LOG_FILE" 2>/dev/null || true
}

# Print log file path
lg_log_path() {
    if [ -z "$LG_LOG_FILE" ]; then
        lg_log_init
    fi
    printf '%s' "$LG_LOG_FILE"
}
