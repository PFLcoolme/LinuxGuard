#!/bin/sh
# core/output.sh - Codex-CLI-style report rendering for LinuxGuard
# The data layer (lg_finding / results file) is unchanged; rendering uses
# core/ui.sh primitives for a clean, aligned terminal presentation.

LG_VERSION='1.2.0'
LG_RESULTS_FILE=''
LG_QUIET=0
LG_NO_COLOR=0

# Initialize result storage
lg_output_init() {
    LG_RESULTS_FILE=$(lg_mktemp)
    : > "$LG_RESULTS_FILE"
}

# Clean up result storage
lg_output_cleanup() {
    if [ -n "$LG_RESULTS_FILE" ] && [ -f "$LG_RESULTS_FILE" ]; then
        rm -f "$LG_RESULTS_FILE"
    fi
}

# Record a finding
# Usage: lg_finding severity module rule title result evidence description recommendation
lg_finding() {
    if [ -z "$LG_RESULTS_FILE" ]; then
        lg_output_init
    fi
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" >> "$LG_RESULTS_FILE"
}

# Print banner
lg_print_banner() {
    [ "$LG_QUIET" -eq 1 ] && return
    lg_ui_init
    printf '\n'
    lg_ui_banner "$LG_VERSION" "Security Audit / 安全审计   ·   AUDIT MODE / 审计模式"
}

# Print system information section
lg_print_system_info() {
    [ "$LG_QUIET" -eq 1 ] && return
    lg_ui_section "SYSTEM / 系统信息"
    lg_ui_kv 24 "OS / 操作系统" "$LG_OS_NAME ${LG_OS_VERSION}"
    lg_ui_kv 24 "Kernel / 内核" "$LG_KERNEL"
    lg_ui_kv 24 "Architecture / 架构" "$LG_ARCH"
    lg_ui_kv 24 "Uptime / 运行时间" "$LG_UPTIME"
    if lg_is_root; then
        lg_ui_kv 24 "Privileges / 权限" "$(lg_c_green 'root')"
    else
        lg_ui_kv 24 "Privileges / 权限" "$(lg_c_yellow 'non-root / 非 root（部分检查受限）')"
    fi
    lg_ui_kv 24 "Package manager / 包管理器" "$LG_PACKAGE_MANAGER"
}

# Print a section header (kept for external callers)
lg_print_section() {
    [ "$LG_QUIET" -eq 1 ] && return
    lg_ui_section "$1"
}

# Print a single finding in detail (verbose mode)
lg_print_finding() {
    _sev=$1 _module=$2 _rule=$3 _title=$4
    _result=$5 _evidence=$6 _desc=$7 _recommend=$8
    printf '\n'
    printf '  %s  %s  %s\n' "$(lg_c_dim '│')" \
        "$(lg_ui_tag "$_sev")" "$(lg_c_bold "$_rule")"
    lg_ui_note "$(printf '%s %s' "$(lg_ui_padto 'Check / 检查' 16)" "$_title")"
    lg_ui_note "$(printf '%s %s' "$(lg_ui_padto 'Module / 模块' 16)" "$_module")"
    lg_ui_note "$(printf '%s %s' "$(lg_ui_padto 'Status / 状态' 16)" "$_result")"
    lg_ui_note "$(printf '%s %s' "$(lg_ui_padto 'Evidence / 证据' 16)" "$_evidence")"
    lg_ui_note "$(printf '%s %s' "$(lg_ui_padto 'Risk / 风险' 16)" "$_desc")"
    lg_ui_note "$(printf '%s %s' "$(lg_ui_padto 'Remediation / 建议' 16)" "$_recommend")"
}

# Print findings grouped by module as a tree.
# A pre-pass marks each row with whether it is the last of its group so the
# tree can draw a proper └─ terminator. Uses a tab-separated stream:
#   group \t last(0/1) \t severity \t rule \t title
lg_print_compact_findings() {
    if [ ! -s "$LG_RESULTS_FILE" ]; then
        lg_ui_note "$(lg_c_green 'No findings recorded / 未记录任何结果。')"
        return
    fi
    _esc=$(printf '\033')
    awk -F'|' 'BEGIN{OFS="\t"}
        { m[NR]=$2; s[NR]=$1; r[NR]=$3; t[NR]=$4; n=NR }
        END{
            for(i=1;i<=n;i++){
                last=1
                for(j=i+1;j<=n;j++) if(m[j]==m[i]) { last=0; break }
                print m[i], last, s[i], r[i], t[i]
            }
        }' "$LG_RESULTS_FILE" > "$LG_RESULTS_FILE.ui"

    _last_group=''
    _max=$((LG_UI_COLS - 22))
    [ "$_max" -lt 24 ] && _max=24
    while IFS='	' read -r _g _last _sev _rule _title; do
        if [ "$_g" != "$_last_group" ]; then
            printf '\n'
            lg_ui_group "$_g"
            _last_group="$_g"
        fi
        _short=$(printf '%s' "$_title" | awk -v max="$_max" '{ if(length($0)>max) print substr($0,1,max-1)"…"; else print }')
        _tag=$(lg_ui_tag "$_sev")
        lg_ui_tree "$_last" "$_tag" "$_short"
    done < "$LG_RESULTS_FILE.ui"
    rm -f "$LG_RESULTS_FILE.ui"
}

# Composite summary line with all severity counts + score card.
lg_print_summary() {
    lg_collect_stats
    _score=$(lg_security_score)

    lg_ui_section "SUMMARY / 审计汇总"
    # Two aligned rows: counts, then a legend. Each block is padded by
    # display width (lg_ui_padto) so CJK glyphs / ANSI never shift columns.
    _sum_fmt() {
        lg_ui_padto "$(printf '%s %2d' "$1" "$2")" 7
    }
    printf '  %s%s%s%s%s%s%s\n' \
        "$(_sum_fmt "$(lg_c_red '●')" "$LG_SC_CRITICAL")" \
        "$(_sum_fmt "$(lg_c_red '●')" "$LG_SC_HIGH")" \
        "$(_sum_fmt "$(lg_c_yellow '●')" "$LG_SC_MEDIUM")" \
        "$(_sum_fmt "$(lg_c_blue '●')" "$LG_SC_LOW")" \
        "$(_sum_fmt "$(lg_c_green '✓')" "$LG_SC_PASS")" \
        "$(_sum_fmt "$(lg_c_magenta '○')" "$LG_SC_UNKNOWN")" \
        "$(_sum_fmt "$(lg_c_dim '○')" "$LG_SC_SKIP")"
    printf '  %s\n' "$(lg_c_dim 'CRIT   HIGH   MED    LOW    PASS   UNKN   SKIP')"
    printf '  %s\n' "$(lg_c_dim '严重   高危   中危   低危   通过   未知   跳过')"

    lg_ui_section "SECURITY SCORE / 安全评分"
    printf '  %s  %s  %s\n' \
        "$(lg_ui_bar "$_score" 30)" \
        "$(lg_c_bold "$(printf '%3d%%' "$_score")")" \
        "$(lg_ui_grade "$_score")"
    printf '  %s\n' "$(lg_c_dim "$(printf 'Findings / 发现项: %d   Issues / 问题项: %d   Passed / 通过: %d' "$LG_SC_TOTAL" "$LG_SC_ISSUES" "$LG_SC_PASS")")"

    printf '\n'
    if [ "$LG_SC_CRITICAL" -gt 0 ] || [ "$LG_SC_HIGH" -gt 0 ]; then
        lg_ui_note "$(lg_c_red 'Review critical/high findings immediately / 请立即处理严重与高危项。')"
    elif [ "$LG_SC_MEDIUM" -gt 0 ]; then
        lg_ui_note "$(lg_c_yellow 'Review medium findings when possible / 请适时处理中危项。')"
    else
        lg_ui_note "$(lg_c_green 'No significant issues detected / 未发现明显问题。')"
    fi
    printf '\n'
}

# Print full detailed report
lg_print_report() {
    lg_print_banner
    lg_print_system_info
    if [ ! -s "$LG_RESULTS_FILE" ]; then
        lg_ui_section "SECURITY AUDIT / 安全审计"
        lg_ui_note "No findings recorded / 未记录任何结果。"
        return
    fi
    lg_ui_section "SECURITY AUDIT / 安全审计   ·   FINDINGS / 发现项"
    lg_print_compact_findings
    lg_print_summary
}

# Print detailed findings (verbose mode)
lg_print_verbose() {
    lg_print_banner
    lg_print_system_info
    if [ ! -s "$LG_RESULTS_FILE" ]; then
        lg_ui_note "No findings recorded / 未记录任何结果。"
        return
    fi
    lg_ui_section "SECURITY AUDIT / 安全审计   ·   DETAILS / 明细"
    while IFS='|' read -r _sev _module _rule _title _result _evidence _desc _recommend; do
        lg_print_finding "$_sev" "$_module" "$_rule" "$_title" \
            "$_result" "$_evidence" "$_desc" "$_recommend"
    done < "$LG_RESULTS_FILE"
    lg_print_summary
}

# Export a plain-text (ANSI-free) report to LG_REPORT_FILE.
# Re-renders the whole report with LG_NO_COLOR=1 and tees to the file.
lg_export_report() {
    [ -z "$LG_REPORT_FILE" ] && return 0
    _esc=$(printf '\033')
    {
        printf 'LinuxGuard v%s - Security Audit Report / 安全审计报告\n' "$LG_VERSION"
        printf 'Generated / 生成时间: %s\n' "$(lg_timestamp)"
        printf 'Host / 主机: %s %s (%s)\n' "$LG_OS_NAME" "$LG_OS_VERSION" "$LG_KERNEL"
        printf '\n'
        _score=$(lg_security_score)
        lg_collect_stats
        printf 'Security Score / 安全评分: %s/100  (%s)\n' "$_score" "$(lg_ui_grade "$_score")"
        printf 'Totals / 统计: CRIT=%d HIGH=%d MED=%d LOW=%d PASS=%d UNKN=%d SKIP=%d (total=%d)\n' \
            "$LG_SC_CRITICAL" "$LG_SC_HIGH" "$LG_SC_MEDIUM" "$LG_SC_LOW" \
            "$LG_SC_PASS" "$LG_SC_UNKNOWN" "$LG_SC_SKIP" "$LG_SC_TOTAL"
        printf '\n'
        printf '%s\n' '--- Findings / 发现项 -----------------------------------------------'
        awk -F'|' '{ printf "[%s] %s | %s | %s\n", $1, $3, $4, $6 }' "$LG_RESULTS_FILE"
        printf '\n'
        printf '%s\n' '--- Repair feasibility / 修复可行性 -------------------------------'
        lg_repair_stats
        printf 'Auto-repairable / 可自动修复: %d   Manual / 需手工处理: %d\n' \
            "$LG_SC_REPAIRABLE" "$LG_SC_MANUAL"
        printf 'By level / 按等级: L1=%d L2=%d L3=%d L4=%d\n' \
            "$LG_SC_L1" "$LG_SC_L2" "$LG_SC_L3" "$LG_SC_L4"
    } > "$LG_REPORT_FILE" 2>/dev/null
    if [ -f "$LG_REPORT_FILE" ]; then
        printf '\n'
        lg_ui_note "$(printf 'Report saved / 报告已保存: %s' "$(lg_c_cyan "$LG_REPORT_FILE")")"
    else
        printf 'Warning: cannot write report to %s\n' "$LG_REPORT_FILE" >&2
    fi
}
