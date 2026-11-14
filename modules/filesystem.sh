#!/bin/sh
# modules/filesystem.sh - Filesystem & mount hardening module
# Read-only: /proc/mounts, /etc/fstab, stat and find only. Nothing is remounted.

_lg_fs_clean() {
    printf '%s' "$1" | tr '\n|' ';/' | cut -c1-260
}

# _lg_fs_mount RULE NAME PATTERN IMPACT FIX
_lg_fs_mount() {
    _title='Filesystem / 文件系统'
    _hits=$(grep -E "$3" /proc/mounts 2>/dev/null | head -n 3)
    if [ ! -r /proc/mounts ]; then
        lg_finding "SKIP" "$_title" "$1" "$2" "Skipped / 跳过" \
            "/proc/mounts unreadable / /proc/mounts 不可读" \
            "Mount table is unavailable / 无法获取挂载表。" \
            "Ensure procfs is mounted / 请确认 procfs 已挂载。"
    elif [ -n "$_hits" ]; then
        lg_finding "MEDIUM" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "$(_lg_fs_clean "$_hits")" "$4" "$5"
    else
        lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
            "No matching mount option found / 未发现匹配的挂载项" "$4" \
            "No action required / 无需操作。"
    fi
}

# _lg_fs_fstab RULE NAME KEYWORD IMPACT FIX
_lg_fs_fstab() {
    _title='Filesystem / 文件系统'
    if [ ! -r /etc/fstab ]; then
        lg_finding "UNKNOWN" "$_title" "$1" "$2" "Unknown / 未知" \
            "/etc/fstab unreadable / /etc/fstab 不可读" \
            "Cannot verify persistent mount policy / 无法验证持久化挂载策略。" \
            "Ensure /etc/fstab is readable / 请确认 /etc/fstab 可读。"
        return
    fi
    _hits=$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/fstab 2>/dev/null | grep -E "$3" | head -n 3)
    if [ -n "$_hits" ]; then
        lg_finding "MEDIUM" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "$(_lg_fs_clean "$_hits")" "$4" "$5"
    else
        lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
            "No matching fstab entry / 无匹配的 fstab 条目" "$4" \
            "No action required / 无需操作。"
    fi
}

lg_run_filesystem() {
    : "${LG_FS_SHARED_TMP_DIRS:=/tmp /var/tmp /dev/shm}"
    _lg_fs_mount "FS_WORLD_WRITABLE_TMP" "Noexec on /tmp / /tmp 的 noexec 挂载" \
        "/tmp .*[[:space:]]rw[[:space:],]" \
        "World-writable /tmp without noexec allows payload execution / 未加 noexec 的全局可写 /tmp 可被用于执行载荷。" \
        "Mount /tmp with noexec,nosuid,nodev / 以 noexec,nosuid,nodev 挂载 /tmp。"

    _lg_fs_mount "FS_DEV_SHM_EXEC" "Noexec on /dev/shm / /dev/shm 的 noexec 挂载" \
        "/dev/shm .*[[:space:]]rw[[:space:],]" \
        "Executable shared memory is a common malware staging area / 可执行的共享内存是常见的恶意软件暂存区。" \
        "Mount /dev/shm with noexec,nosuid,nodev / 以 noexec,nosuid,nodev 挂载 /dev/shm。"

    _lg_fs_mount "FS_VAR_TMP_EXEC" "Noexec on /var/tmp / /var/tmp 的 noexec 挂载" \
        "/var/tmp .*[[:space:]]rw[[:space:],]" \
        "Persistent temp space should not allow direct execution / 持久化临时目录不应允许直接执行程序。" \
        "Mount /var/tmp with noexec,nosuid,nodev / 以 noexec,nosuid,nodev 挂载 /var/tmp。"

    # 4. World-writable files outside standard temp dirs (bounded sample).
    _title='Filesystem / 文件系统'
    if lg_command_exists find; then
        _ww=$(find / -xdev -type f -perm -0002 -not -path '/proc/*' \
            -not -path '/sys/*' -not -path '/dev/*' \
            -not -path '/tmp/*' -not -path '/var/tmp/*' \
            -print 2>/dev/null | head -n 5)
        if [ -n "$_ww" ]; then
            lg_finding "HIGH" "$_title" "FS_WORLD_WRITABLE_FILES" \
                "World-writable files outside temp dirs / 临时目录外存在全局可写文件" \
                "Risk found / 发现风险" "$(_lg_fs_clean "$_ww")" \
                "Any local user can modify these files, enabling privilege escalation / 任意本地用户均可修改这些文件，可能导致提权。" \
                "Remove the world-write bit and review each file / 清除全局写位并逐一核查。"
        else
            lg_finding "PASS" "$_title" "FS_WORLD_WRITABLE_FILES" \
                "World-writable files outside temp dirs / 临时目录外存在全局可写文件" \
                "Compliant / 合规" "No world-writable regular files sampled / 抽样未发现全局可写普通文件" \
                "No unexpected world-writable files detected / 未发现异常的全局可写文件。" \
                "No action required / 无需操作。"
        fi
    else
        lg_finding "SKIP" "$_title" "FS_WORLD_WRITABLE_FILES" \
            "World-writable files outside temp dirs / 临时目录外存在全局可写文件" \
            "Skipped / 跳过" "find unavailable / find 不可用" \
            "Cannot enumerate world-writable files / 无法枚举全局可写文件。" \
            "Install findutils / 请安装 findutils。"
    fi

    # 5. Unowned files (no valid user or group).
    if lg_command_exists find; then
        _no=$(find / -xdev -type f -nouser -o -type f -nogroup 2>/dev/null | head -n 5)
        if [ -n "$_no" ]; then
            lg_finding "MEDIUM" "$_title" "FS_UNOWNED_FILES" \
                "Files without a valid owner / 存在无有效属主的文件" \
                "Risk found / 发现风险" "$(_lg_fs_clean "$_no")" \
                "Unowned files may be leftovers of deleted accounts or an intrusion / 无属主文件可能是已删除账户或入侵的残留。" \
                "Assign a legitimate owner or remove the files / 指定合法属主或删除这些文件。"
        else
            lg_finding "PASS" "$_title" "FS_UNOWNED_FILES" \
                "Files without a valid owner / 存在无有效属主的文件" \
                "Compliant / 合规" "No unowned regular files sampled / 抽样未发现无属主普通文件" \
                "No orphaned files detected / 未发现孤儿文件。" \
                "No action required / 无需操作。"
        fi
    else
        lg_finding "SKIP" "$_title" "FS_UNOWNED_FILES" \
            "Files without a valid owner / 存在无有效属主的文件" \
            "Skipped / 跳过" "find unavailable / find 不可用" \
            "Cannot enumerate unowned files / 无法枚举无属主文件。" \
            "Install findutils / 请安装 findutils。"
    fi

    _lg_fs_fstab "FS_FSTAB_USER" "User-mountable fstab entries / fstab 中的 user 挂载项" \
        "[[:space:],]user[[:space:],]" \
        "The user option lets unprivileged users mount filesystems / user 选项允许非特权用户挂载文件系统，可能引入 SUID 风险。" \
        "Remove the user option or add nosuid,nodev / 移除 user 选项或补充 nosuid,nodev。"

    _lg_fs_fstab "FS_FSTAB_NODEV" "Missing nodev on non-root mounts / 非根挂载缺少 nodev" \
        "[[:space:]]/(home|var|tmp|data|opt)[[:space:]].*defaults" \
        "Mounts using plain defaults may permit device files / 使用纯 defaults 的挂载可能允许创建设备文件。" \
        "Add nodev (and nosuid,noexec where suitable) / 增加 nodev（适宜时再加 nosuid,noexec）。"

    # 8. Sticky bit on world-writable directories.
    _sticky=''
    for _d in $LG_FS_SHARED_TMP_DIRS; do
        [ -d "$_d" ] || continue
        _m=$(lg_file_mode "$_d" 2>/dev/null)
        case "$_m" in
            1777) ;;
            *) _sticky="${_sticky}${_sticky:+; }${_d}=${_m:-unknown}" ;;
        esac
    done
    if [ -n "$_sticky" ]; then
        lg_finding "MEDIUM" "$_title" "FS_TMP_STICKY_BIT" \
            "Sticky bit on shared temp directories / 共享临时目录的粘滞位" \
            "Risk found / 发现风险" "$_sticky" \
            "Without the sticky bit users can delete each other's files / 缺少粘滞位时用户可互相删除文件。" \
            "chmod 1777 on the affected directories / 对相关目录执行 chmod 1777。"
    else
        lg_finding "PASS" "$_title" "FS_TMP_STICKY_BIT" \
            "Sticky bit on shared temp directories / 共享临时目录的粘滞位" \
            "Compliant / 合规" "Checked /tmp,/var/tmp,/dev/shm" \
            "Shared temp directories are protected by the sticky bit / 共享临时目录受粘滞位保护。" \
            "No action required / 无需操作。"
    fi

    # 9. Core dump configuration.
    if [ -r /proc/sys/kernel/core_pattern ]; then
        _core=$(cat /proc/sys/kernel/core_pattern 2>/dev/null | head -n 1)
        case "$_core" in
            '|'*)
                lg_finding "LOW" "$_title" "FS_CORE_DUMPS" \
                    "Core dumps piped to a helper / 核心转储通过管道交给辅助程序" \
                    "Informational / 信息" "$(_lg_fs_clean "$_core")" \
                    "A pipe helper requires careful review; core files may contain secrets / 管道辅助程序需仔细核查，核心文件可能含敏感数据。" \
                    "Verify the helper is trusted or set core_pattern=core / 确认辅助程序可信，或设置 core_pattern=core。" ;;
            *)
                lg_finding "PASS" "$_title" "FS_CORE_DUMPS" \
                    "Core dumps written to files / 核心转储写入普通文件" \
                    "Compliant / 合规" "$(_lg_fs_clean "$_core")" \
                    "No external pipe helper is configured / 未配置外部管道辅助程序。" \
                    "No action required / 无需操作。" ;;
        esac
    else
        lg_finding "SKIP" "$_title" "FS_CORE_DUMPS" \
            "Core dump configuration / 核心转储配置" "Skipped / 跳过" \
            "/proc/sys/kernel/core_pattern unavailable / 该 proc 条目不可用" \
            "Cannot inspect core dump behaviour / 无法检查核心转储行为。" \
            "Ensure /proc/sys is mounted / 请确认 /proc/sys 已挂载。"
    fi

    # 10. /home mounted on a separate partition.
    _home=$(grep -E '[[:space:]]/home[[:space:]]' /proc/mounts 2>/dev/null | head -n 1)
    if [ -n "$_home" ]; then
        lg_finding "PASS" "$_title" "FS_HOME_SEPARATE" \
            "/home on a separate partition / /home 位于独立分区" \
            "Compliant / 合规" "$(_lg_fs_clean "$_home")" \
            "A separate /home limits disk-filling and enables nodev,nosuid / 独立 /home 可限制磁盘占满并便于施加 nodev,nosuid。" \
            "No action required / 无需操作。"
    else
        lg_finding "LOW" "$_title" "FS_HOME_SEPARATE" \
            "/home on a separate partition / /home 位于独立分区" \
            "Informational / 信息" "No dedicated /home mount found / 未发现独立的 /home 挂载" \
            "User data shares the root filesystem / 用户数据与根文件系统共用分区。" \
            "Consider a dedicated /home mount with nodev,nosuid / 可考虑独立 /home 并加 nodev,nosuid。"
    fi
}
