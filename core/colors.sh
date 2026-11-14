#!/bin/sh
# core/colors.sh - Terminal color handling for LinuxGuard
# Uses inline ANSI escapes (no tput dependency, robust when TERM is unset).

# Default: colors disabled until a capable terminal is detected
LG_COLOR_ENABLED=0

# ANSI palette (empty when colors are off)
LG_RESET=''
LG_BOLD=''
LG_DIM=''
LG_RED=''
LG_GREEN=''
LG_YELLOW=''
LG_BLUE=''
LG_MAGENTA=''
LG_CYAN=''
LG_WHITE=''
LG_BG_RED=''
LG_BG_GREEN=''

# Initialize colors based on terminal capability.
# Colors are enabled only on an interactive tty unless LG_FORCE_COLOR=1
# (useful for demos/tests). LG_NO_COLOR always wins.
lg_colors_init() {
    _enable=0
    if [ "${LG_NO_COLOR:-0}" -ne 1 ] && { [ -t 1 ] || [ "${LG_FORCE_COLOR:-0}" -eq 1 ]; }; then
        _enable=1
    fi

    if [ "$_enable" -eq 1 ]; then
        _e=$(printf '\033')
        LG_COLOR_ENABLED=1
        LG_RESET="${_e}[0m"
        LG_BOLD="${_e}[1m"
        LG_DIM="${_e}[2m"
        LG_RED="${_e}[31m"
        LG_GREEN="${_e}[32m"
        LG_YELLOW="${_e}[33m"
        LG_BLUE="${_e}[34m"
        LG_MAGENTA="${_e}[35m"
        LG_CYAN="${_e}[36m"
        LG_WHITE="${_e}[37m"
        LG_BG_RED="${_e}[41m"
        LG_BG_GREEN="${_e}[42m"
    fi
}

# Disable colors explicitly (also blanks the palette)
lg_colors_disable() {
    LG_COLOR_ENABLED=0
    LG_RESET=''
    LG_BOLD=''
    LG_DIM=''
    LG_RED=''
    LG_GREEN=''
    LG_YELLOW=''
    LG_BLUE=''
    LG_MAGENTA=''
    LG_CYAN=''
    LG_WHITE=''
    LG_BG_RED=''
    LG_BG_GREEN=''
}

# Color wrappers (identical API to the original implementation)
lg_c_red()     { printf '%s%s%s' "$LG_RED" "$1" "$LG_RESET"; }
lg_c_green()   { printf '%s%s%s' "$LG_GREEN" "$1" "$LG_RESET"; }
lg_c_yellow()  { printf '%s%s%s' "$LG_YELLOW" "$1" "$LG_RESET"; }
lg_c_blue()    { printf '%s%s%s' "$LG_BLUE" "$1" "$LG_RESET"; }
lg_c_magenta() { printf '%s%s%s' "$LG_MAGENTA" "$1" "$LG_RESET"; }
lg_c_cyan()    { printf '%s%s%s' "$LG_CYAN" "$1" "$LG_RESET"; }
lg_c_white()   { printf '%s%s%s' "$LG_WHITE" "$1" "$LG_RESET"; }
lg_c_bold()    { printf '%s%s%s' "$LG_BOLD" "$1" "$LG_RESET"; }
lg_c_dim()     { printf '%s%s%s' "$LG_DIM" "$1" "$LG_RESET"; }
