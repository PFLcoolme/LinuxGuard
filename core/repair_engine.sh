#!/bin/sh
# core/repair_engine.sh - Repair orchestration for LinuxGuard

# Prompt user for confirmation
# Usage: lg_confirm prompt
# Returns 0 if user confirms, 1 otherwise
lg_confirm() {
    _prompt=$1
    printf '  %s  %s  %s ' \
        "$(lg_c_dim '│')" \
        "$(lg_c_yellow '?')" \
        "$(printf '%s %s' "$_prompt" "$(lg_c_dim '[y/N]')")"
    read -r _answer
    case "$_answer" in
        [Yy]|[Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

# Print repair plan without executing
lg_repair_dry_run() {
    _plan=$(lg_analyze_findings)
    if [ -z "$_plan" ]; then
        lg_ui_note "$(lg_c_green 'No repairable findings / 没有可修复项。')"
        return 0
    fi

    lg_ui_section "REPAIR PLAN / 修复计划   ·   DRY-RUN / 试运行"
    _total=$(printf '%s\n' "$_plan" | grep -c '[^[:space:]]')
    _idx=0
    printf '%s\n' "$_plan" | while IFS='|' read -r _sev _rule _level _func _title _evidence; do
        [ -z "$_rule" ] && continue
        _idx=$((_idx + 1))
        _last=0
        [ "$_idx" -eq "$_total" ] && _last=1
        _short=$(printf '%s' "$_title" | awk -v max=40 '{ if(length($0)>max) print substr($0,1,max-1)"…"; else print }')
        lg_ui_tree "$_last" "$(lg_ui_level_tag "$_level")" \
            "$(printf '%-28s %s  %s' "$_rule" "$_short" "$(lg_c_dim "-> ${_func}()")")"
    done

    lg_repair_stats
    printf '\n'
    lg_ui_note "$(printf '%s %s   %s %s   %s' \
        "$(lg_c_dim 'Auto-repairable / 可自动修复:')" "$(lg_c_bold "$LG_SC_REPAIRABLE")" \
        "$(lg_c_dim 'Manual / 需手工:')" "$(lg_c_bold "$LG_SC_MANUAL")" \
        "$(lg_c_dim "L1=$LG_SC_L1 L2=$LG_SC_L2 L3=$LG_SC_L3 L4=$LG_SC_L4")")"
    lg_ui_note "$(lg_c_green 'No changes were made / 未做任何更改。')"
}

# Execute a single repair with backup, validation, and rollback
# Print a labelled repair step line: "│ <tag> message"
_lg_repair_step() {
    printf '  %s  %s  %s\n' "$(lg_c_dim '│')" "$1" "$2"
}

lg_repair_execute_one() {
    _sev=$1
    _rule=$2
    _level=$3
    _func=$4
    _title=$5
    _evidence=$6

    printf '\n'
    printf '  %s  %s  %s\n' "$(lg_c_dim '│')" \
        "$(lg_ui_level_tag "$_level")" "$(lg_c_bold "$_rule")  $_title"
    _lg_repair_step "$(lg_c_dim '·      ')" \
        "$(printf '%s %s' "$(lg_c_dim 'Evidence / 证据:')" "$_evidence")"

    # Load the repair function if not already loaded
    if ! type "$_func" >/dev/null 2>&1; then
        lg_load_repair_for_rule "$_rule"
    fi

    # Backup target file(s) before repair
    _backup_target=$(lg_repair_backup_target "$_rule")
    _backup_path=''
    if [ -n "$_backup_target" ]; then
        _backup_path=$(lg_backup_file "$_backup_target")
        if [ -z "$_backup_path" ]; then
            _lg_repair_step "$(lg_ui_result SKIP)" "$(lg_c_red 'Backup failed; skipping repair / 备份失败，跳过修复。')"
            lg_log "REPAIR_SKIPPED" "$_rule" "backup failed"
            return 1
        fi
        _lg_repair_step "$(lg_c_dim '·      ')" \
            "$(printf '%s %s' "$(lg_c_dim 'Backup / 备份:')" "$_backup_path")"
    fi

    # Execute repair
    if "$_func" "$@"; then
        _lg_repair_step "$(lg_ui_result OK)" "Repair executed / 修复已执行"
        lg_log "REPAIR_OK" "$_rule" "$_evidence"

        # Validate if applicable
        if ! lg_repair_validate "$_rule"; then
            _lg_repair_step "$(lg_ui_result ROLLBACK)" "$(lg_c_yellow 'Validation failed - rolling back / 验证失败 - 正在回滚')"
            if [ -n "$_backup_path" ]; then
                lg_rollback_file "$_backup_target" "$_backup_path"
            fi
            lg_log "VALIDATE_FAILED_ROLLBACK" "$_rule" ""
            return 1
        fi

        # Re-run detection for this rule to verify
        if lg_repair_verify "$_rule"; then
            _lg_repair_step "$(lg_ui_result OK)" "Verification / 验证: $(lg_c_green 'PASS / 通过')"
            lg_log "VERIFY_OK" "$_rule" ""
            return 0
        else
            _lg_repair_step "$(lg_ui_result ROLLBACK)" "$(lg_c_yellow 'Verification / 验证: FAIL / 失败 - rolling back / 正在回滚')"
            if [ -n "$_backup_path" ]; then
                lg_rollback_file "$_backup_target" "$_backup_path"
            fi
            lg_log "VERIFY_FAILED" "$_rule" "rolled back"
            return 1
        fi
    else
        _lg_repair_step "$(lg_ui_result FAIL)" "$(lg_c_red 'Repair failed / 修复失败。')"
        if [ -n "$_backup_path" ]; then
            lg_rollback_file "$_backup_target" "$_backup_path"
        fi
        lg_log "REPAIR_FAILED" "$_rule" "$_evidence"
        return 1
    fi
}

# Print a session footer (used by all repair modes)
_lg_repair_footer() {
    printf '\n'
    lg_ui_section "REPAIR SUMMARY / 修复汇总"
    lg_ui_note "$(printf '%s %s   %s %s   %s %s' \
        "$(lg_c_dim 'Applied / 已修复:')" "$(lg_c_green "$(printf '%d' "$1")")" \
        "$(lg_c_dim 'Skipped / 已跳过:')" "$(lg_c_yellow "$(printf '%d' "$2")")" \
        "$(lg_c_dim 'Failed / 失败:')" "$(lg_c_red "$(printf '%d' "$3")")")"
}

# Iterate the plan from a temp file (NOT a pipe) so counters survive the
# loop and repair verification can safely re-read LG_RESULTS_FILE.
_lg_plan_file() {
    printf '%s\n' "$1" > "$LG_RESULTS_FILE.plan"
}

# Run interactive repair
lg_repair_interactive() {
    _plan=$(lg_analyze_findings)
    if [ -z "$_plan" ]; then
        lg_ui_note "$(lg_c_green 'No repairable findings / 没有可修复项。')"
        return 0
    fi

    lg_ui_section "REPAIR PLAN / 修复计划   ·   INTERACTIVE / 逐项确认"
    _lg_plan_file "$_plan"
    _done=0
    _skipped=0
    _failed=0
    while IFS='|' read -r _sev _rule _level _func _title _evidence; do
        [ -z "$_rule" ] && continue
        if lg_confirm "Repair / 修复 $(lg_c_bold "$_rule") ?"; then
            if lg_repair_execute_one "$_sev" "$_rule" "$_level" "$_func" "$_title" "$_evidence"; then
                _done=$((_done + 1))
            else
                _failed=$((_failed + 1))
            fi
        else
            _lg_repair_step "$(lg_ui_result SKIP)" "Skipped by user / 用户已跳过"
            _skipped=$((_skipped + 1))
        fi
    done < "$LG_RESULTS_FILE.plan"
    rm -f "$LG_RESULTS_FILE.plan"
    _lg_repair_footer "$_done" "$_skipped" "$_failed"
}

# Run safe (L1 only) repair
lg_repair_safe() {
    _plan=$(lg_analyze_findings)
    if [ -z "$_plan" ]; then
        lg_ui_note "$(lg_c_green 'No repairable findings / 没有可修复项。')"
        return 0
    fi

    lg_ui_section "REPAIR PLAN / 修复计划   ·   SAFE / 仅低风险 L1"
    _lg_plan_file "$_plan"
    _done=0
    _skipped=0
    _failed=0
    while IFS='|' read -r _sev _rule _level _func _title _evidence; do
        [ -z "$_rule" ] && continue
        if [ "$_level" = "L1" ]; then
            if lg_repair_execute_one "$_sev" "$_rule" "$_level" "$_func" "$_title" "$_evidence"; then
                _done=$((_done + 1))
            else
                _failed=$((_failed + 1))
            fi
        else
            _lg_repair_step "$(lg_ui_result SKIP)" "Skip L2-L4 / 跳过 L2-L4 项: $_title"
            _skipped=$((_skipped + 1))
        fi
    done < "$LG_RESULTS_FILE.plan"
    rm -f "$LG_RESULTS_FILE.plan"
    _lg_repair_footer "$_done" "$_skipped" "$_failed"
}

# Run all repairs with level-based confirmation
lg_repair_all() {
    _plan=$(lg_analyze_findings)
    if [ -z "$_plan" ]; then
        lg_ui_note "$(lg_c_green 'No repairable findings / 没有可修复项。')"
        return 0
    fi

    lg_ui_section "REPAIR PLAN / 修复计划   ·   ALL / 全部修复"
    lg_repair_stats
    lg_ui_note "$(printf '%s %s   %s %s' \
        "$(lg_c_dim 'Risky / 高风险:')" "$(lg_c_red "$(printf 'L3=%d L4=%d' "$LG_SC_L3" "$LG_SC_L4")")" \
        "$(lg_c_dim 'Total / 合计:')" "$(lg_c_bold "$LG_SC_REPAIRABLE")")"

    if [ "$LG_SC_L3" -gt 0 ] || [ "$LG_SC_L4" -gt 0 ]; then
        if ! lg_confirm "Continue with all repairs / 是否继续全部修复"; then
            lg_ui_note "$(lg_c_yellow 'Aborted / 已中止。')"
            return 1
        fi
    fi

    _lg_plan_file "$_plan"
    _done=0
    _failed=0
    while IFS='|' read -r _sev _rule _level _func _title _evidence; do
        [ -z "$_rule" ] && continue
        if lg_repair_execute_one "$_sev" "$_rule" "$_level" "$_func" "$_title" "$_evidence"; then
            _done=$((_done + 1))
        else
            _failed=$((_failed + 1))
        fi
    done < "$LG_RESULTS_FILE.plan"
    rm -f "$LG_RESULTS_FILE.plan"
    _lg_repair_footer "$_done" 0 "$_failed"
}

# Main repair dispatcher
lg_repair_run() {
    case "$LG_FIX_MODE" in
        dry-run)
            lg_repair_dry_run
            ;;
        safe)
            lg_repair_safe
            ;;
        interactive)
            lg_repair_interactive
            ;;
        all)
            lg_repair_all
            ;;
        *)
            lg_ui_note "$(lg_c_red "Unknown fix mode / 未知修复模式: $LG_FIX_MODE")"
            return 1
            ;;
    esac
}

# Load repair script for a given rule
lg_load_repair_for_rule() {
    _rule=$1
    case "$_rule" in
        SSH_*)
            lg_load_repair "ssh"
            ;;
        UID0_EXTRA_USERS|EMPTY_PASSWORDS|UNUSUAL_SHELL|STALE_PASSWORDS)
            lg_load_repair "users"
            ;;
        SUDO_*)
            lg_load_repair "sudo"
            ;;
        FIREWALL_*)
            lg_load_repair "firewall"
            ;;
        KERNEL_*)
            lg_load_repair "kernel"
            ;;
        PERM_*)
            lg_load_repair "permissions"
            ;;
        DOCKER_SOCKET)
            lg_load_repair "docker"
            ;;
        *)
            printf 'No repair script mapped for rule: %s\n' "$_rule" >&2
            ;;
    esac
}

# Determine which file(s) to backup before repairing a rule
lg_repair_backup_target() {
    _rule=$1
    case "$_rule" in
        SSH_*)
            printf '%s' "$LG_SSHD_CONFIG"
            ;;
        SUDO_*|SUDOERS_PERMISSIONS)
            printf '/etc/sudoers'
            ;;
        KERNEL_*)
            printf '/etc/sysctl.d/99-linuxguard.conf'
            ;;
        PERM_PASSWD)
            printf '/etc/passwd'
            ;;
        PERM_GROUP)
            printf '/etc/group'
            ;;
        PERM_SHADOW)
            printf '/etc/shadow'
            ;;
        DOCKER_SOCKET)
            printf '/var/run/docker.sock'
            ;;
        *)
            printf ''
            ;;
    esac
}

# Validate repair based on rule type
lg_repair_validate() {
    _rule=$1
    case "$_rule" in
        SSH_*)
            lg_validate_ssh
            ;;
    esac
}

# Verify a repair by re-running the relevant module and checking the rule status
lg_repair_verify() {
    _rule=$1
    case "$_rule" in
        SSH_*)
            lg_run_ssh
            ;;
        UID0_EXTRA_USERS|EMPTY_PASSWORDS|UNUSUAL_SHELL|STALE_PASSWORDS)
            lg_run_users
            ;;
        SUDO_*|SUDOERS_PERMISSIONS)
            lg_run_sudo
            ;;
        FIREWALL_*)
            lg_run_firewall
            ;;
        KERNEL_*)
            lg_run_kernel
            ;;
        PERM_*)
            lg_run_permissions
            ;;
        DOCKER_SOCKET)
            lg_run_docker
            ;;
        *)
            return 0
            ;;
    esac

    # Check whether the original finding is still present
    if grep -qE "^[^|]*\\|${_rule}\\|" "$LG_RESULTS_FILE" 2>/dev/null; then
        # Re-read the severity; if PASS, verification succeeded
        _new_sev=$(grep -E "^[^|]*\\|${_rule}\\|" "$LG_RESULTS_FILE" | tail -n 1 | cut -d'|' -f1)
        if [ "$_new_sev" = "PASS" ]; then
            return 0
        fi
    fi
    return 1
}
