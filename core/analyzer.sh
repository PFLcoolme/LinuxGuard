#!/bin/sh
# core/analyzer.sh - Analyze findings and determine repair actions

# Build a list of repairable findings from the results file.
# Output format: SEVERITY|RULE|LEVEL|FUNCTION|TITLE|EVIDENCE
lg_analyze_findings() {
    while IFS='|' read -r _sev _module _rule _title _result _evidence _desc _recommend; do
        _func=$(lg_policy_get_function "$_rule")
        _level=$(lg_policy_get_level "$_rule")
        if [ -n "$_func" ] && [ -n "$_level" ]; then
            # Skip PASS, UNKNOWN, SKIP findings
            case "$_sev" in
                PASS|UNKNOWN|SKIP) continue ;;
            esac
            printf '%s|%s|%s|%s|%s|%s\n' \
                "$_sev" "$_rule" "$_level" "$_func" "$_title" "$_evidence"
        fi
    done < "$LG_RESULTS_FILE"
}

# Count repairable findings by level
lg_analyze_count_by_level() {
    _list=$1
    _level=$2
    printf '%s' "$_list" | grep -cE "\\|${_level}\\|" 2>/dev/null || printf '0'
}

# Get level numeric weight (L1 < L4)
lg_level_weight() {
    case "$1" in
        L1) printf '1' ;;
        L2) printf '2' ;;
        L3) printf '3' ;;
        L4) printf '4' ;;
        *) printf '9' ;;
    esac
}

# Label a level for display
lg_level_label() {
    case "$1" in
        L1) printf 'L1-low-risk/低风险' ;;
        L2) printf 'L2-medium-risk/中风险' ;;
        L3) printf 'L3-high-risk/高风险' ;;
        L4) printf 'L4-critical-risk/严重风险' ;;
        *) printf '%s' "$1" ;;
    esac
}

# ---------------------------------------------------------------------------
# Scoring & statistics (consumed by the report layer)
# ---------------------------------------------------------------------------

# Deduction weight per severity for the composite security score.
lg_score_weight() {
    case "$1" in
        CRITICAL) printf '25' ;;
        HIGH)     printf '12' ;;
        MEDIUM)   printf '5'  ;;
        LOW)      printf '2'  ;;
        UNKNOWN)  printf '1'  ;;
        *)        printf '0'  ;;
    esac
}

# Count results by severity and stash into globals:
#   LG_SC_CRITICAL / HIGH / MEDIUM / LOW / PASS / UNKNOWN / SKIP / TOTAL
lg_collect_stats() {
    LG_SC_CRITICAL=0
    LG_SC_HIGH=0
    LG_SC_MEDIUM=0
    LG_SC_LOW=0
    LG_SC_PASS=0
    LG_SC_UNKNOWN=0
    LG_SC_SKIP=0
    LG_SC_TOTAL=0
    while IFS='|' read -r _sev _rest; do
        case "$_sev" in
            CRITICAL) LG_SC_CRITICAL=$((LG_SC_CRITICAL + 1)) ;;
            HIGH)     LG_SC_HIGH=$((LG_SC_HIGH + 1)) ;;
            MEDIUM)   LG_SC_MEDIUM=$((LG_SC_MEDIUM + 1)) ;;
            LOW)      LG_SC_LOW=$((LG_SC_LOW + 1)) ;;
            PASS)     LG_SC_PASS=$((LG_SC_PASS + 1)) ;;
            UNKNOWN)  LG_SC_UNKNOWN=$((LG_SC_UNKNOWN + 1)) ;;
            SKIP)     LG_SC_SKIP=$((LG_SC_SKIP + 1)) ;;
        esac
        LG_SC_TOTAL=$((LG_SC_TOTAL + 1))
    done < "$LG_RESULTS_FILE"
    LG_SC_ISSUES=$((LG_SC_CRITICAL + LG_SC_HIGH + LG_SC_MEDIUM + LG_SC_LOW))
}

# Composite security score (0-100). Weighted deductions from 100, floored at 0.
# Result printed as a bare integer.
lg_security_score() {
    _score=100
    _ded=0
    while IFS='|' read -r _sev _rest; do
        _w=$(lg_score_weight "$_sev")
        _ded=$((_ded + _w))
    done < "$LG_RESULTS_FILE"
    _score=$((100 - _ded))
    [ "$_score" -lt 0 ] && _score=0
    printf '%s' "$_score"
}

# Repair feasibility stats over all actionable (non PASS/UNKNOWN/SKIP) findings.
# Stashes into globals: LG_SC_REPAIRABLE / LG_SC_MANUAL / LG_SC_L1..L4
lg_repair_stats() {
    LG_SC_REPAIRABLE=0
    LG_SC_MANUAL=0
    LG_SC_L1=0
    LG_SC_L2=0
    LG_SC_L3=0
    LG_SC_L4=0
    while IFS='|' read -r _sev _module _rule _title _result _evidence _desc _recommend; do
        case "$_sev" in
            PASS|UNKNOWN|SKIP) continue ;;
        esac
        _func=$(lg_policy_get_function "$_rule")
        if [ -n "$_func" ]; then
            LG_SC_REPAIRABLE=$((LG_SC_REPAIRABLE + 1))
            _lv=$(lg_policy_get_level "$_rule")
            case "$_lv" in
                L1) LG_SC_L1=$((LG_SC_L1 + 1)) ;;
                L2) LG_SC_L2=$((LG_SC_L2 + 1)) ;;
                L3) LG_SC_L3=$((LG_SC_L3 + 1)) ;;
                L4) LG_SC_L4=$((LG_SC_L4 + 1)) ;;
            esac
        else
            LG_SC_MANUAL=$((LG_SC_MANUAL + 1))
        fi
    done < "$LG_RESULTS_FILE"
}
