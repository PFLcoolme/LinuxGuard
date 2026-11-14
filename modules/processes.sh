#!/bin/sh
# modules/processes.sh - Suspicious running-process detection module
#
# Read-only by design: inspects /proc only. It never signals, traces, kills or
# otherwise interacts with a process. /proc is used instead of `ps` so results
# do not depend on procps/busybox command-line flags.

# Collapse arbitrary process text into one safe evidence field.
# lg_finding separates columns with '|' and rows with '\n': both must be
# removed, otherwise a crafted cmdline could inject fake result rows.
_lg_proc_clean() {
    printf '%s' "$1" | tr '\n|' ';/' | \
        sed 's/[[:space:]][[:space:]]*/ /g' | cut -c1-300
}

# Emit "pid|exe|comm|cmdline" for every readable process to stdout.
# Each field is cleaned first, so the stream is safe to parse with IFS='|'.
_lg_proc_snapshot() {
    for _p in /proc/[0-9]*; do
        [ -d "$_p" ] || continue
        _pid=${_p##*/}
        _exe=$(readlink "$_p/exe" 2>/dev/null) || _exe=''
        _comm=''
        [ -r "$_p/comm" ] && _comm=$(cat "$_p/comm" 2>/dev/null)
        _cmd=''
        [ -r "$_p/cmdline" ] && _cmd=$(tr '\000' ' ' < "$_p/cmdline" 2>/dev/null)
        printf '%s|%s|%s|%s\n' "$_pid" \
            "$(_lg_proc_clean "$_exe")" \
            "$(_lg_proc_clean "$_comm")" \
            "$(_lg_proc_clean "$_cmd")"
    done
}

# Print the first suspicious keyword found in a text; return 1 if none.
_lg_proc_keyword_hit() {
    _txt=$(printf '%s' "$1" | lg_tolower)
    for _kw in $2; do
        [ -z "$_kw" ] && continue
        case "$_txt" in
            *"$_kw"*) printf '%s' "$_kw"; return 0 ;;
        esac
    done
    return 1
}

# Append at most 5 evidence fragments (keeps output short and bounded).
_lg_proc_add_evidence() {
    _cur=$1 _n=$2 _frag=$3
    if [ "$_n" -le 5 ]; then
        printf '%s%s%s' "$_cur" "${_cur:+; }" "$_frag"
    else
        printf '%s' "$_cur"
    fi
}

lg_run_processes() {
    : "${LG_PROC_SUSPICIOUS_NAMES:=xmrig minerd cpuminer ethminer cgminer kworkerds kthreaddds sysupdate networkservice cryptominer}"
    : "${LG_PROC_MINER_KEYWORDS:=stratum+tcp cryptonight monero xmr.pool donate-level coinhive}"

    if [ ! -d /proc/1 ] || [ ! -r /proc/1/comm ]; then
        lg_finding \
            "UNKNOWN" \
            "Suspicious Processes / 可疑进程" \
            "PROC_PROCFS_UNAVAILABLE" \
            "Cannot inspect processes / 无法检查进程" \
            "Unknown / 未知" \
            "/proc is not readable / /proc 不可读" \
            "Process inspection requires a readable procfs / 进程检查需要可读的 procfs。" \
            "Run on a standard Linux host with /proc mounted / 请在挂载 /proc 的标准 Linux 主机上运行。"
        return
    fi

    # Snapshot to a temp file and read it by redirection (NOT a pipe) so the
    # counters below survive the loop in this POSIX sh.
    _snapfile="${LG_RESULTS_FILE}.procs"
    _lg_proc_snapshot > "$_snapfile" 2>/dev/null
    _total=$(grep -c . "$_snapfile" 2>/dev/null || printf '0')

    _deleted=''   _deleted_n=0
    _tmpexec=''   _tmpexec_n=0
    _susp=''      _susp_n=0

    while IFS='|' read -r _pid _exe _comm _cmd; do
        [ -z "$_pid" ] && continue

        # 1. Executable deleted from disk while the process still runs:
        #    a classic technique used to hide the on-disk payload.
        case "$_exe" in
            *'(deleted)'*)
                _deleted_n=$((_deleted_n + 1))
                _deleted=$(_lg_proc_add_evidence "$_deleted" "$_deleted_n" "pid=${_pid}:${_exe}")
                ;;
        esac

        # 2. Processes executing from world-writable temporary directories.
        case "$_exe" in
            /tmp/*|/var/tmp/*|/dev/shm/*)
                _tmpexec_n=$((_tmpexec_n + 1))
                _tmpexec=$(_lg_proc_add_evidence "$_tmpexec" "$_tmpexec_n" "pid=${_pid}:${_exe}")
                ;;
        esac

        # 3. Known miner / backdoor indicators in name, command line, exe.
        _hit=$(_lg_proc_keyword_hit "$_comm $_cmd $_exe" \
            "$LG_PROC_SUSPICIOUS_NAMES $LG_PROC_MINER_KEYWORDS")
        if [ -n "$_hit" ]; then
            _susp_n=$((_susp_n + 1))
            _susp=$(_lg_proc_add_evidence "$_susp" "$_susp_n" "pid=${_pid}(${_comm}):${_hit}")
        fi
    done < "$_snapfile"
    rm -f "$_snapfile"

    # Non-root cannot resolve /proc/<pid>/exe for processes of other users;
    # explicitly tell the reader that coverage is partial.
    if ! lg_is_root; then
        lg_finding \
            "LOW" \
            "Suspicious Processes / 可疑进程" \
            "PROC_VISIBILITY" \
            "Non-root process visibility is limited / 非 root 进程可见性受限" \
            "Informational / 信息" \
            "Running as uid=$(id -u); other users' exe links may be unreadable / 当前 uid=$(id -u)，其他用户的 exe 链接可能不可读" \
            "Some hidden or cross-user processes cannot be fully inspected / 部分隐藏或跨用户进程无法完整检查。" \
            "Re-run as root for complete process coverage / 请以 root 重新运行以获得完整覆盖。"
    fi

    if [ "$_deleted_n" -gt 0 ]; then
        lg_finding \
            "HIGH" \
            "Suspicious Processes / 可疑进程" \
            "PROC_DELETED_EXE" \
            "Processes running from deleted executables / 存在运行于已删除可执行文件的进程" \
            "Risk found / 发现风险" \
            "${_deleted_n} found: ${_deleted}" \
            "A deleted on-disk binary while the process lives is often used to hide malware / 二进制被删除而进程仍存活，常用于隐藏恶意程序。" \
            "Inspect each PID (/proc/<pid>/exe, cwd, maps) and terminate confirmed threats / 检查每个 PID 的 exe、cwd、maps，并终止已确认的威胁。"
    else
        lg_finding \
            "PASS" \
            "Suspicious Processes / 可疑进程" \
            "PROC_DELETED_EXE" \
            "No deleted-executable processes detected / 未检测到已删除可执行文件的进程" \
            "Compliant / 合规" \
            "Checked ${_total} process(es) / 已检查 ${_total} 个进程" \
            "No running process has an unlinked executable / 没有运行中的进程使用已删除的可执行文件。" \
            "No action required / 无需操作。"
    fi

    if [ "$_tmpexec_n" -gt 0 ]; then
        lg_finding \
            "HIGH" \
            "Suspicious Processes / 可疑进程" \
            "PROC_TEMP_EXEC" \
            "Processes executing from temporary directories / 存在从临时目录运行的进程" \
            "Risk found / 发现风险" \
            "${_tmpexec_n} found: ${_tmpexec}" \
            "Binaries launched from /tmp, /var/tmp or /dev/shm are a common dropper staging location / 从临时目录启动二进制是常见的投放/暂存手法。" \
            "Verify each binary's origin and remove unauthorised files / 核实每个二进制的来源并清除未授权文件。"
    else
        lg_finding \
            "PASS" \
            "Suspicious Processes / 可疑进程" \
            "PROC_TEMP_EXEC" \
            "No processes executing from temporary directories / 无从临时目录运行的进程" \
            "Compliant / 合规" \
            "Checked /tmp, /var/tmp, /dev/shm / 已检查 /tmp、/var/tmp、/dev/shm" \
            "No executable was launched from a world-writable temp directory / 未发现从全局可写临时目录启动的可执行文件。" \
            "No action required / 无需操作。"
    fi

    if [ "$_susp_n" -gt 0 ]; then
        lg_finding \
            "HIGH" \
            "Suspicious Processes / 可疑进程" \
            "PROC_SUSPICIOUS_NAME" \
            "Processes matching miner/backdoor indicators / 进程命中矿机/后门特征" \
            "Risk found / 发现风险" \
            "${_susp_n} matched: ${_susp}" \
            "Known miner, reverse-shell or backdoor keywords suggest possible compromise / 命中已知矿机、反弹 Shell 或后门关键词，可能存在入侵。" \
            "Confirm each match against legitimate workloads before taking action / 处置前先与合法业务负载核对每个命中项。"
    else
        lg_finding \
            "PASS" \
            "Suspicious Processes / 可疑进程" \
            "PROC_SUSPICIOUS_NAME" \
            "No known suspicious process indicators / 未发现已知可疑进程特征" \
            "Compliant / 合规" \
            "Keyword list: ${LG_PROC_SUSPICIOUS_NAMES} ${LG_PROC_MINER_KEYWORDS}" \
            "No process name or command line matched the known indicator list / 没有进程名或命令行命中已知特征列表。" \
            "No action required / 无需操作。"
    fi

    lg_finding \
        "LOW" \
        "Suspicious Processes / 可疑进程" \
        "PROC_INVENTORY" \
        "Process inventory collected / 已收集进程清单" \
        "Informational / 信息" \
        "${_total} process(es) inspected via /proc / 通过 /proc 检查了 ${_total} 个进程" \
        "A baseline count helps spot unexpected long-running or injected processes / 基线数量有助于发现异常的长期运行或注入进程。" \
        "Review ps auxww and correlate with listening sockets / 结合 ps auxww 与监听套接字复查。"
}
