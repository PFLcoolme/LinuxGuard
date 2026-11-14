#!/bin/sh
# core/utils.sh - POSIX Shell utility functions for LinuxGuard

# Check if a command exists in PATH
lg_command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running as root
lg_is_root() {
    [ "$(id -u)" -eq 0 ]
}

# Trim leading and trailing whitespace
lg_trim() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Convert string to lowercase (ASCII only)
lg_tolower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# Convert string to uppercase (ASCII only)
lg_toupper() {
    printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

# Check if file exists and is readable
lg_file_readable() {
    [ -r "$1" ]
}

# Check if a string contains a substring (POSIX, no [[ ])
lg_contains() {
    case "$1" in
        *"$2"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Get file mode in octal (e.g. 644)
lg_file_mode() {
    if lg_command_exists stat; then
        stat -c '%a' "$1" 2>/dev/null
    else
        ls -l "$1" 2>/dev/null | awk '{print $1}' | sed 's/^[-dlcbsp]//' | awk '
        {
            mode = 0
            for (i = 1; i <= 9; i++) {
                c = substr($0, i, 1)
                bit = 0
                if (c == "r" && (i == 1 || i == 4 || i == 7)) bit = 4
                if (c == "w" && (i == 2 || i == 5 || i == 8)) bit = 2
                if (c == "x" && (i == 3 || i == 6 || i == 9)) bit = 1
                if (c == "s" && (i == 3 || i == 6)) bit = 1
                if (c == "S" && (i == 3 || i == 6)) bit = 0
                if (c == "t" && i == 9) bit = 1
                if (i <= 3) mode += bit * 100
                else if (i <= 6) mode += bit * 10
                else mode += bit
            }
            printf "%03d\n", mode
        }'
    fi
}

# Print current timestamp in ISO-like format
lg_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Securely create a temporary file; falls back to mktemp behavior
lg_mktemp() {
    if lg_command_exists mktemp; then
        mktemp
    else
        _lg_rand=$(awk 'BEGIN{srand(); printf "%d", rand() * 100000}')
        _lg_tmp="/tmp/linuxguard.$$.$_lg_rand"
        (umask 077 && touch "$_lg_tmp")
        printf '%s' "$_lg_tmp"
    fi
}
