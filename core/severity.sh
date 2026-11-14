#!/bin/sh
# core/severity.sh - Risk severity definitions and helpers for LinuxGuard

# Severity levels as numeric values for easy comparison
LG_SEV_CRITICAL=5
LG_SEV_HIGH=4
LG_SEV_MEDIUM=3
LG_SEV_LOW=2
LG_SEV_PASS=1
LG_SEV_UNKNOWN=0
LG_SEV_SKIP=-1

# Convert severity name to numeric value
lg_severity_to_num() {
    case "$1" in
        CRITICAL) printf '%s' "$LG_SEV_CRITICAL" ;;
        HIGH)     printf '%s' "$LG_SEV_HIGH" ;;
        MEDIUM)   printf '%s' "$LG_SEV_MEDIUM" ;;
        LOW)      printf '%s' "$LG_SEV_LOW" ;;
        PASS)     printf '%s' "$LG_SEV_PASS" ;;
        SKIP)     printf '%s' "$LG_SEV_SKIP" ;;
        *)        printf '%s' "$LG_SEV_UNKNOWN" ;;
    esac
}

# Convert numeric value to severity name
lg_severity_to_name() {
    case "$1" in
        5) printf 'CRITICAL' ;;
        4) printf 'HIGH' ;;
        3) printf 'MEDIUM' ;;
        2) printf 'LOW' ;;
        1) printf 'PASS' ;;
        0) printf 'UNKNOWN' ;;
        -1) printf 'SKIP' ;;
        *) printf 'UNKNOWN' ;;
    esac
}

# Get colorized bilingual severity label
lg_severity_label() {
    _sev_name=$1
    case "$_sev_name" in
        CRITICAL) lg_c_red "CRITICAL/严重" ;;
        HIGH)     lg_c_red "HIGH/高危" ;;
        MEDIUM)   lg_c_yellow "MEDIUM/中危" ;;
        LOW)      lg_c_blue "LOW/低危" ;;
        PASS)     lg_c_green "PASS/通过" ;;
        SKIP)     lg_c_dim "SKIP/跳过" ;;
        UNKNOWN)  lg_c_magenta "UNKNOWN/未知" ;;
        *)        printf '%s' "$_sev_name" ;;
    esac
}

# Return true if first severity is worse than second
lg_severity_is_worse() {
    _a=$(lg_severity_to_num "$1")
    _b=$(lg_severity_to_num "$2")
    [ "$_a" -gt "$_b" ]
}

# Aggregate severity: return the worse of two
lg_severity_max() {
    _a=$(lg_severity_to_num "$1")
    _b=$(lg_severity_to_num "$2")
    if [ "$_a" -ge "$_b" ]; then
        printf '%s' "$1"
    else
        printf '%s' "$2"
    fi
}
