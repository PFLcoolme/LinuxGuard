#!/bin/sh
# core/validator.sh - Post-repair validation utilities

# Validate SSH configuration
lg_validate_ssh() {
    if ! lg_command_exists sshd; then
        printf 'sshd not available, skipping SSH config validation.\n'
        return 0
    fi

    if sshd -t 2>/dev/null; then
        lg_log "VALIDATE" "sshd_config" "sshd -t passed"
        return 0
    else
        lg_log "VALIDATE_FAILED" "sshd_config" "sshd -t failed"
        return 1
    fi
}

# Validate a sysctl value is set as expected
lg_validate_sysctl() {
    _key=$1
    _expected=$2

    if ! lg_command_exists sysctl; then
        return 1
    fi

    _actual=$(sysctl -n "$_key" 2>/dev/null)
    if [ "$_actual" = "$_expected" ]; then
        lg_log "VALIDATE" "$_key" "value=$_actual"
        return 0
    else
        lg_log "VALIDATE_FAILED" "$_key" "expected=$_expected actual=$_actual"
        return 1
    fi
}

# Generic validation wrapper
lg_validate_repair() {
    _type=$1
    shift

    case "$_type" in
        ssh)
            lg_validate_ssh "$@"
            ;;
        sysctl)
            lg_validate_sysctl "$@"
            ;;
        *)
            printf 'No validator available for type: %s\n' "$_type"
            return 1
            ;;
    esac
}
