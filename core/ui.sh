#!/bin/sh
# core/ui.sh - Codex-CLI-style terminal UI primitives for LinuxGuard
# Rounded panels, dim guide lines, tree branches, compact status tags,
# section rules and a score bar. All helpers are POSIX sh.
# Width math is display-column aware (CJK = 2 columns) so mixed CN/EN
# labels stay aligned. Internal vars use the _u_ prefix (no `local` in sh).

# ---------------------------------------------------------------------------
# Geometry
# ---------------------------------------------------------------------------

# Resolve drawing width into LG_UI_COLS. Prefers LG_UI_WIDTH, then COLUMNS,
# then a tty probe, else a 78-column default that also works for reports.
lg_ui_init() {
    LG_UI_COLS=78
    _u_c=${LG_UI_WIDTH:-}
    if [ -z "$_u_c" ]; then _u_c=${COLUMNS:-}; fi
    [ "$_u_c" = "0" ] && _u_c=''
    if [ -z "$_u_c" ] && [ -t 1 ]; then
        _u_c=$(stty size 2>/dev/null | cut -d' ' -f2)
    fi
    case "${_u_c:-}" in
        ''|*[!0-9]*) _u_c='' ;;
    esac
    if [ -n "$_u_c" ] && [ "$_u_c" -ge 40 ] && [ "$_u_c" -le 200 ]; then
        LG_UI_COLS=$_u_c
    fi
    [ "$LG_UI_COLS" -gt 96 ] && LG_UI_COLS=96
}

# Display width of a string (ANSI stripped, CJK = 2 cols). Bare number.
lg_ui_dwidth() {
    _u_esc=$(printf '\033')
    printf '%s\n' "$1" | sed "s/${_u_esc}\[[0-9;]*m//g" | wc -L | tr -d '[:space:]'
}

# Repeat a single character N times (no trailing newline).
lg_ui_repeat() {
    _u_c=$1
    _u_n=$2
    _u_out=''
    while [ "$_u_n" -gt 0 ]; do
        _u_out="${_u_out}${_u_c}"
        _u_n=$((_u_n - 1))
    done
    printf '%s' "$_u_out"
}

# Right-pad a string to a given display width.
lg_ui_padto() {
    _u_s=$1
    _u_target=$2
    _u_cw=$(lg_ui_dwidth "$_u_s")
    _u_pad=$((_u_target - _u_cw))
    [ "$_u_pad" -lt 0 ] && _u_pad=0
    printf '%s%s' "$_u_s" "$(lg_ui_repeat ' ' "$_u_pad")"
}

# Clip a string to a maximum display width, appending "…" if cut.
# Relies on awk character semantics (gawk/mawk in UTF-8 locale): substr()
# and length() operate on characters, not bytes. Width: ASCII=1, CJK=2.
lg_ui_clip() {
    awk -v max="$2" '
    {
        n=length($0); out=""; w=0; cut=0
        for (i=1; i<=n; i++) {
            c=substr($0,i,1)
            if (c==sprintf("%c",27)) {           # ANSI escape: copy, skip
                out=out c
                i++
                while (i<=n) {
                    d=substr($0,i,1); out=out d
                    if (d ~ /[A-Za-z]/) break
                    i++
                }
                continue
            }
            cw = (c ~ /[^\x00-\x7f]/) ? 2 : 1
            if (w + cw > max - 1) { cut=1; break }
            out=out c; w += cw
        }
        printf "%s%s\n", out, (cut ? "…" : "")
    }
    ' <<EOF
$1
EOF
}

# ---------------------------------------------------------------------------
# Panel primitives
# ---------------------------------------------------------------------------

# A full content row inside a panel: "│ <content>... │"
lg_ui_panel_row() {
    _u_w=$1
    _u_content=$2
    _u_inner=$((_u_w - 4))
    _u_clipped=$(lg_ui_clip "$_u_content" "$_u_inner")
    _u_cw=$(lg_ui_dwidth "$_u_clipped")
    _u_pad=$((_u_inner - _u_cw))
    [ "$_u_pad" -lt 0 ] && _u_pad=0
    printf '%s %s%s %s\n' \
        "$(lg_c_dim '│')" "$_u_clipped" \
        "$(lg_ui_repeat ' ' "$_u_pad")" "$(lg_c_dim '│')"
}

# A horizontal rule, optionally with an embedded title: "── Title ──────"
lg_ui_rule() {
    _u_w=${1:-$LG_UI_COLS}
    _u_title=${2:-}
    _u_prefix=''
    _u_fill=$_u_w
    if [ -n "$_u_title" ]; then
        _u_prefix="─ ${_u_title} "
        _u_pw=$(lg_ui_dwidth "$_u_prefix")
        _u_fill=$((_u_w - _u_pw))
        [ "$_u_fill" -lt 2 ] && _u_fill=2
    fi
    _u_line="${_u_prefix}$(lg_ui_repeat '─' "$_u_fill")"
    printf '%s\n' "$(lg_c_dim "$_u_line")"
}

# Section header: blank line + titled rule.
lg_ui_section() {
    printf '\n'
    lg_ui_rule "$LG_UI_COLS" "$1"
}

# The rounded header banner.
lg_ui_banner() {
    _u_ver=$1
    _u_sub=$2
    _u_w=$LG_UI_COLS
    _u_inner=$((_u_w - 2))
    _u_bar=$(lg_ui_repeat '─' "$_u_inner")
    printf '%s\n' "$(lg_c_dim "╭${_u_bar}╮")"
    lg_ui_panel_row "$_u_w" " $(lg_c_cyan '●') $(lg_c_bold 'LinuxGuard')   $(lg_c_dim "v${_u_ver}")"
    lg_ui_panel_row "$_u_w" "   $(lg_c_dim "$_u_sub")"
    printf '%s\n' "$(lg_c_dim "╰${_u_bar}╯")"
}

# ---------------------------------------------------------------------------
# Content primitives
# ---------------------------------------------------------------------------

# A dim vertical guide line followed by a note: "│  text"
lg_ui_note() {
    printf '%s  %s\n' "$(lg_c_dim '│')" "$1"
}

# Key / value line with aligned key column.
# lg_ui_kv <key-width> <key> <value>
lg_ui_kv() {
    _u_kw=$1
    _u_key=$2
    _u_val=$3
    _u_kpadded=$(lg_ui_padto "$_u_key" "$_u_kw")
    printf '  %s  %s\n' "$(lg_c_dim "$_u_kpadded")" "$_u_val"
}

# Group (module) heading: "▸ Name"
lg_ui_group() {
    printf '  %s  %s\n' "$(lg_c_cyan '▸')" "$(lg_c_bold "$1")"
}

# A tree item with a branch and a status tag.
# lg_ui_tree <last:0|1> <tag> <text>
lg_ui_tree() {
    _u_last=$1
    _u_tag=$2
    _u_text=$3
    if [ "$_u_last" -eq 1 ]; then _u_br='└─'; else _u_br='├─'; fi
    printf '    %s %s  %s\n' "$(lg_c_dim "$_u_br")" "$_u_tag" "$_u_text"
}

# Compact status tag for tree rows.
lg_ui_tag() {
    case "$1" in
        CRITICAL) lg_c_red     '● CRIT' ;;
        HIGH)     lg_c_red     '● HIGH' ;;
        MEDIUM)   lg_c_yellow  '● MED ' ;;
        LOW)      lg_c_blue    '● LOW ' ;;
        PASS)     lg_c_green   '✓ PASS' ;;
        UNKNOWN)  lg_c_magenta '○ UNKN' ;;
        SKIP)     lg_c_dim     '○ SKIP' ;;
        *)        lg_c_dim     '○    ?' ;;
    esac
}

# Compact repair-level tag (L1..L4) for the repair plan tree.
lg_ui_level_tag() {
    case "$1" in
        L1) lg_c_green   'L1 低 ' ;;
        L2) lg_c_yellow  'L2 中 ' ;;
        L3) lg_c_red     'L3 高 ' ;;
        L4) lg_c_red     'L4 危 ' ;;
        *)  lg_c_dim     "$1    " ;;
    esac
}

# Compact operation-result tag for repair progress lines.
lg_ui_result() {
    case "$1" in
        OK)     lg_c_green  '✓ OK   ' ;;
        FAIL)   lg_c_red    '✗ FAIL ' ;;
        SKIP)   lg_c_dim    '○ SKIP ' ;;
        ROLLBACK) lg_c_yellow '↺ ROLBK' ;;
        *)      lg_c_dim    '·      ' ;;
    esac
}

# ---------------------------------------------------------------------------
# Score bar
# ---------------------------------------------------------------------------

# Colour a score bar. Colour follows the score (green/amber/red).
# lg_ui_bar <score 0-100> [width]
lg_ui_bar() {
    _u_score=$1
    _u_w=${2:-28}
    [ "$_u_score" -lt 0 ] && _u_score=0
    [ "$_u_score" -gt 100 ] && _u_score=100
    _u_f=$((_u_score * _u_w / 100))
    _u_e=$((_u_w - _u_f))
    _u_filled=$(lg_ui_repeat '█' "$_u_f")
    _u_empty=$(lg_ui_repeat '░' "$_u_e")
    if [ "$_u_score" -ge 80 ]; then
        _u_col=$LG_GREEN
    elif [ "$_u_score" -ge 50 ]; then
        _u_col=$LG_YELLOW
    else
        _u_col=$LG_RED
    fi
    printf '%s%s%s%s' "$_u_col" "$_u_filled" "$LG_DIM" "$_u_empty"
    printf '%s' "$LG_RESET"
}

# Grade label for a score (bilingual, coloured).
lg_ui_grade() {
    case "$1" in
        9[0-9]|100) lg_c_green  'A / 优秀' ;;
        8[0-9])     lg_c_green  'B / 良好' ;;
        7[0-9])     lg_c_yellow 'C / 一般' ;;
        6[0-9])     lg_c_yellow 'D / 及格' ;;
        5[0-9])     lg_c_yellow 'E / 偏低' ;;
        *)          lg_c_red    'F / 危险' ;;
    esac
}
