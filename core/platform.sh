#!/bin/sh
# core/platform.sh - Platform and distribution detection for LinuxGuard

LG_OS_NAME='Unknown'
LG_OS_VERSION='Unknown'
LG_OS_ID='unknown'
LG_OS_ID_LIKE=''
LG_KERNEL=''
LG_ARCH=''
LG_UPTIME=''
LG_PACKAGE_MANAGER='unknown'
LG_PACKAGE_MANAGER_CMD=''

# Load /etc/os-release fields
lg_detect_os_release() {
    if [ -r /etc/os-release ]; then
        while IFS='=' read -r _key _val; do
            _k=$(lg_trim "$_key")
            _v=$(printf '%s' "$_val" | sed 's/^"//;s/"$//')
            case "$_k" in
                NAME) LG_OS_NAME="$_v" ;;
                VERSION_ID) LG_OS_VERSION="$_v" ;;
                ID) LG_OS_ID=$(lg_tolower "$_v") ;;
                ID_LIKE) LG_OS_ID_LIKE=$(lg_tolower "$_v") ;;
            esac
        done < /etc/os-release
    fi

    # Fallbacks
    if [ "$LG_OS_NAME" = 'Unknown' ] && [ -r /etc/debian_version ]; then
        LG_OS_NAME='Debian'
        LG_OS_ID='debian'
    fi
    if [ "$LG_OS_NAME" = 'Unknown' ] && [ -r /etc/redhat-release ]; then
        LG_OS_NAME=$(head -n 1 /etc/redhat-release)
        LG_OS_ID='rhel'
    fi
    if [ "$LG_OS_NAME" = 'Unknown' ] && [ -r /etc/alpine-release ]; then
        LG_OS_NAME='Alpine Linux'
        LG_OS_ID='alpine'
    fi
    if [ "$LG_OS_NAME" = 'Unknown' ] && [ -r /etc/arch-release ]; then
        LG_OS_NAME='Arch Linux'
        LG_OS_ID='arch'
    fi

    # Rolling-release distributions may not set VERSION_ID
    if [ "$LG_OS_VERSION" = 'Unknown' ] && [ "$LG_OS_ID" = 'arch' ]; then
        LG_OS_VERSION='rolling release'
    fi
}

# Detect kernel, architecture, uptime
lg_detect_system() {
    LG_KERNEL=$(uname -r 2>/dev/null || printf 'unknown')
    LG_ARCH=$(uname -m 2>/dev/null || printf 'unknown')
    if lg_command_exists uptime; then
        LG_UPTIME=$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk -F',' '{print $1}' | sed 's/^ *//')
    else
        LG_UPTIME=$(awk '{printf "%d days, %02d:%02d:%02d", $1/86400, ($1%86400)/3600, ($1%3600)/60, $1%60}' /proc/uptime 2>/dev/null)
    fi
}

# Detect package manager
lg_detect_package_manager() {
    if lg_command_exists apt-get; then
        LG_PACKAGE_MANAGER='apt'
        LG_PACKAGE_MANAGER_CMD='apt-get'
    elif lg_command_exists dnf; then
        LG_PACKAGE_MANAGER='dnf'
        LG_PACKAGE_MANAGER_CMD='dnf'
    elif lg_command_exists yum; then
        LG_PACKAGE_MANAGER='yum'
        LG_PACKAGE_MANAGER_CMD='yum'
    elif lg_command_exists pacman; then
        LG_PACKAGE_MANAGER='pacman'
        LG_PACKAGE_MANAGER_CMD='pacman'
    elif lg_command_exists apk; then
        LG_PACKAGE_MANAGER='apk'
        LG_PACKAGE_MANAGER_CMD='apk'
    elif lg_command_exists zypper; then
        LG_PACKAGE_MANAGER='zypper'
        LG_PACKAGE_MANAGER_CMD='zypper'
    fi
}

# Initialize platform detection
lg_platform_init() {
    lg_detect_os_release
    lg_detect_system
    lg_detect_package_manager
}

# Returns true if distro family matches
lg_is_distro() {
    case "$LG_OS_ID" in
        "$1") return 0 ;;
    esac
    case "$LG_OS_ID_LIKE" in
        *"$1"*) return 0 ;;
    esac
    return 1
}
