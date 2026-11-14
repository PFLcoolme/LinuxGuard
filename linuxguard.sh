#!/bin/sh
# linuxguard.sh - LinuxGuard main entry point
# POSIX Shell Linux security audit & repair tool

# POSIX-compatible path resolution for symlinked scripts
_lg_resolve_path() {
    _path=$1
    while [ -L "$_path" ]; do
        _link=$(readlink "$_path" 2>/dev/null) || break
        case "$_link" in
            /*) _path=$_link ;;
            *) _path=$(dirname "$_path")/$_link ;;
        esac
    done
    printf '%s' "$_path"
}

# Determine base directory safely
LG_SCRIPT_PATH=$0
if [ -L "$LG_SCRIPT_PATH" ]; then
    LG_SCRIPT_PATH=$(_lg_resolve_path "$LG_SCRIPT_PATH")
fi
LG_BASE_DIR=$(dirname "$LG_SCRIPT_PATH")
LG_CORE_DIR="${LG_BASE_DIR}/core"

# Load initialization (parses arguments, sets up environment)
if [ -r "${LG_CORE_DIR}/init.sh" ]; then
    . "${LG_CORE_DIR}/init.sh"
else
    printf 'Error: cannot load %s\n' "${LG_CORE_DIR}/init.sh" >&2
    exit 1
fi

lg_init "$@"

# Run detection modules
for _module in $LG_SELECTED_MODULES; do
    case "$_module" in
        system|ssh|users|sudo|firewall|kernel|ports|permissions|packages|cron|docker|logs|processes|malware|vulnscan|netstack|filesystem|auth|audit|services)
            lg_load_module "$_module"
            "lg_run_$_module"
            ;;
        *)
            printf 'Warning: unknown module "%s", skipping.\n' "$_module" >&2
            ;;
    esac
done

# In fix mode, run repair engine after detection
if [ "$LG_MODE" = "fix" ]; then
    # Dry-run only displays a plan and never touches the system, so a
    # non-root preview is allowed for all other fix modes root is required.
    if [ "$LG_FIX_MODE" != "dry-run" ] && ! lg_is_root; then
        printf 'Fix mode requires root privileges. Run with sudo or as root. / 修复模式需要 root 权限，请使用 sudo 或以 root 运行。\n' >&2
        lg_output_cleanup
        exit 1
    fi

    lg_ui_init
    lg_ui_section "REPAIR MODE / 修复模式"
    lg_repair_run
    lg_backup_cleanup
else
    # Output report in scan mode
    if [ "$LG_VERBOSE" -eq 1 ]; then
        lg_print_verbose
    else
        lg_print_report
    fi
    lg_export_report
fi

# Cleanup
lg_output_cleanup

exit 0
