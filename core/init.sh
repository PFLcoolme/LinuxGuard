#!/bin/sh
# core/init.sh - Initialization and CLI parsing for LinuxGuard

LG_BASE_DIR=''
LG_CORE_DIR=''
LG_MODULES_DIR=''
LG_REPAIRS_DIR=''
LG_CONFIG_DIR=''

# Output control defaults
LG_QUIET=0
LG_NO_COLOR=0
LG_VERBOSE=0
LG_FORCE_COLOR=0
LG_REPORT_FILE=''

# Modules available in V1.2
LG_MODULES='system ssh users sudo firewall kernel ports permissions packages cron docker logs processes malware vulnscan netstack filesystem auth audit services'

# Run mode: scan or fix
LG_MODE='scan'
LG_SELECTED_MODULES=''

# Fix mode: dry-run, safe, interactive, all
LG_FIX_MODE=''

# Parse command-line arguments
lg_parse_args() {
    if [ $# -eq 0 ]; then
        LG_MODE='scan'
        LG_SELECTED_MODULES=$LG_MODULES
        return
    fi

    # Detect subcommand
    case "$1" in
        scan)
            LG_MODE='scan'
            shift
            ;;
        fix)
            LG_MODE='fix'
            LG_FIX_MODE='interactive'
            shift
            ;;
        --help|-h|--version|-v)
            # Legacy/global options handled below
            ;;
        *)
            # Legacy behavior: options without subcommand default to scan
            LG_MODE='scan'
            ;;
    esac

    while [ $# -gt 0 ]; do
        case "$1" in
            # Fix mode options
            --dry-run)
                LG_FIX_MODE='dry-run'
                ;;
            --safe)
                LG_FIX_MODE='safe'
                ;;
            --interactive)
                LG_FIX_MODE='interactive'
                ;;
            --all)
                LG_FIX_MODE='all'
                ;;
            # Scan mode options (legacy)
            --quick)
                LG_SELECTED_MODULES=$LG_MODULES
                ;;
            --system)
                LG_SELECTED_MODULES='system'
                ;;
            --ssh)
                LG_SELECTED_MODULES='ssh'
                ;;
            --users)
                LG_SELECTED_MODULES='users'
                ;;
            --sudo)
                LG_SELECTED_MODULES='sudo'
                ;;
            --firewall)
                LG_SELECTED_MODULES='firewall'
                ;;
            --kernel)
                LG_SELECTED_MODULES='kernel'
                ;;
            --ports)
                LG_SELECTED_MODULES='ports'
                ;;
            --permissions)
                LG_SELECTED_MODULES='permissions'
                ;;
            --packages)
                LG_SELECTED_MODULES='packages'
                ;;
            --cron)
                LG_SELECTED_MODULES='cron'
                ;;
            --docker)
                LG_SELECTED_MODULES='docker'
                ;;
            --logs)
                LG_SELECTED_MODULES='logs'
                ;;
            --processes)
                LG_SELECTED_MODULES='processes'
                ;;
            --malware)
                LG_SELECTED_MODULES='malware'
                ;;
            --vulnscan)
                LG_SELECTED_MODULES='vulnscan'
                ;;
            --netstack)
                LG_SELECTED_MODULES='netstack'
                ;;
            --filesystem)
                LG_SELECTED_MODULES='filesystem'
                ;;
            --auth)
                LG_SELECTED_MODULES='auth'
                ;;
            --audit)
                LG_SELECTED_MODULES='audit'
                ;;
            --services)
                LG_SELECTED_MODULES='services'
                ;;
            --threats)
                LG_SELECTED_MODULES='processes malware vulnscan'
                ;;
            --hardening)
                LG_SELECTED_MODULES='netstack filesystem auth audit services'
                ;;
            --network)
                LG_SELECTED_MODULES='firewall ports'
                ;;
            --all-modules)
                LG_SELECTED_MODULES=$LG_MODULES
                ;;
            --no-color)
                LG_NO_COLOR=1
                lg_colors_disable
                ;;
            --color)
                LG_FORCE_COLOR=1
                lg_colors_init
                ;;
            --report)
                shift
                LG_REPORT_FILE=$1
                if [ -z "$LG_REPORT_FILE" ]; then
                    printf 'Error: --report requires a file path / --report 需要指定文件路径\n' >&2
                    exit 1
                fi
                ;;
            --quiet)
                LG_QUIET=1
                ;;
            --verbose)
                LG_VERBOSE=1
                ;;
            --help|-h)
                lg_print_help
                exit 0
                ;;
            --version|-v)
                lg_print_version
                exit 0
                ;;
            *)
                printf 'Unknown option: %s\n' "$1"
                lg_print_help
                exit 1
                ;;
        esac
        shift
    done

    if [ -z "$LG_SELECTED_MODULES" ]; then
        LG_SELECTED_MODULES=$LG_MODULES
    fi

    # Validate fix mode consistency
    if [ "$LG_MODE" = "fix" ] && [ -z "$LG_FIX_MODE" ]; then
        LG_FIX_MODE='interactive'
    fi
}

# Print help
lg_print_help() {
    cat <<EOF
LinuxGuard v${LG_VERSION} - Linux Security Audit & Repair Tool / Linux 安全审计与修复工具

Usage / 用法:
  ./linuxguard.sh [scan] [OPTIONS]       Run security audit (default) / 运行安全审计（默认）
  ./linuxguard.sh fix [OPTIONS]          Run repair mode / 运行修复模式

Scan options / 扫描选项:
  (none)          Run full security audit / 完整安全审计
  --quick         Run full audit with reduced detail / 快速检查
  --system        Run only system information checks / 仅系统信息
  --ssh           Run only SSH configuration checks / 仅 SSH 配置
  --users         Run only user account checks / 仅用户账户
  --sudo          Run only sudo privilege checks / 仅 sudo 权限
  --firewall      Run only firewall checks / 仅防火墙
  --kernel        Run only kernel security checks / 仅内核安全
  --ports         Run only open port checks / 仅开放端口
  --permissions   Run only file permission checks / 仅文件权限
  --packages      Run only package update checks / 仅软件包更新
  --cron          Run only scheduled task checks / 仅计划任务
  --docker        Run only Docker security checks / 仅 Docker 安全
  --logs          Run only authentication log checks / 仅认证日志
  --processes     Run only suspicious process checks / 仅可疑进程
  --malware       Run only malware/rootkit indicator checks / 仅恶意软件与 Rootkit 指标
  --vulnscan      Run only vulnerability posture checks / 仅漏洞态势
  --netstack      Run only network-stack hardening checks / 仅网络协议栈加固
  --filesystem    Run only filesystem/mount checks / 仅文件系统与挂载
  --auth          Run only authentication & password policy checks / 仅认证与口令策略
  --audit         Run only audit & logging checks / 仅审计与日志
  --services      Run only services & autostart checks / 仅服务与自启动
  --threats       Run all threat checks (processes, malware, vulnscan) / 全部威胁检查
  --hardening     Run all 50 hardening checks (V1.2) / 全部 50 项加固检查
  --network       Run network-related checks (firewall, ports) / 网络相关检查
  --all-modules   Run all implemented checks / 运行所有已实现检查

Fix options / 修复选项:
  --dry-run       Show repair plan without making changes / 仅显示修复计划
  --safe          Auto-repair only low-risk (L1) findings / 仅自动修复低风险项
  --interactive   Confirm each repair (default) / 逐项确认修复
  --all           Repair all after summary confirmation / 汇总确认后全部修复

Global options / 全局选项:
  --verbose       Print detailed findings for each check / 打印每项详细结果
  --color         Force coloured output (for demos/screenshots) / 强制彩色输出
  --no-color      Disable colored output / 禁用彩色输出
  --report FILE   Export plain-text report / 导出纯文本报告到文件
  --quiet         Suppress banner and system information / 隐藏 banner 和系统信息
  --help, -h      Show this help message / 显示帮助
  --version, -v   Show version information / 显示版本

Examples / 示例:
  ./linuxguard.sh
  ./linuxguard.sh scan --ssh --verbose
  ./linuxguard.sh scan --threats
  ./linuxguard.sh scan --hardening --verbose
  ./linuxguard.sh fix --dry-run
  ./linuxguard.sh fix --safe

Note / 说明:
  Threat modules are read-only indicators, not a full antivirus/CVE scan.
  威胁模块为只读指标检查，并非完整的杀毒/CVE 扫描。
  Hardening modules are read-only and are never auto-repaired by fix mode.
  加固模块同样只读，修复模式不会自动修改这些检查项。

EOF
}

# Print version
lg_print_version() {
    printf 'LinuxGuard v%s\n' "$LG_VERSION"
}

# Determine base directory relative to main script
lg_init_paths() {
    if [ -n "$LG_BASE_DIR" ]; then
        return
    fi

    # Try to resolve script directory (POSIX, symlinks resolved manually)
    _lg_script=$0
    while [ -L "$_lg_script" ]; do
        _lg_link=$(readlink "$_lg_script" 2>/dev/null) || break
        case "$_lg_link" in
            /*) _lg_script=$_lg_link ;;
            *) _lg_script=$(dirname "$_lg_script")/$_lg_link ;;
        esac
    done

    LG_BASE_DIR=$(dirname "$_lg_script")
    LG_CORE_DIR="${LG_BASE_DIR}/core"
    LG_MODULES_DIR="${LG_BASE_DIR}/modules"
    LG_REPAIRS_DIR="${LG_BASE_DIR}/repairs"
    LG_CONFIG_DIR="${LG_BASE_DIR}/config"
}

# Load a core script
lg_load_core() {
    _core_path="${LG_CORE_DIR}/$1"
    if [ -r "$_core_path" ]; then
        . "$_core_path"
    else
        printf 'Error: cannot load core script: %s\n' "$_core_path" >&2
        exit 1
    fi
}

# Load a detection module
lg_load_module() {
    _module_path="${LG_MODULES_DIR}/$1.sh"
    if [ -r "$_module_path" ]; then
        . "$_module_path"
    else
        printf 'Error: cannot load module: %s\n' "$_module_path" >&2
        exit 1
    fi
}

# Load a repair script
lg_load_repair() {
    _repair_path="${LG_REPAIRS_DIR}/$1_repair.sh"
    if [ -r "$_repair_path" ]; then
        . "$_repair_path"
    else
        printf 'Error: cannot load repair script: %s\n' "$_repair_path" >&2
        exit 1
    fi
}

# Load configuration
lg_load_config() {
    _config="${LG_CONFIG_DIR}/rules.sh"
    if [ -r "$_config" ]; then
        . "$_config"
    fi
    _repair_policy="${LG_CONFIG_DIR}/repair_policy.sh"
    if [ -r "$_repair_policy" ]; then
        . "$_repair_policy"
    fi
}

# Main initialization sequence
lg_init() {
    lg_init_paths
    lg_load_core utils.sh
    lg_load_core colors.sh
    lg_load_core severity.sh
    lg_load_core ui.sh
    lg_load_core platform.sh
    lg_load_core output.sh
    lg_load_core analyzer.sh

    lg_colors_init
    lg_parse_args "$@"

    # Re-evaluate colours after parsing so --color / --no-color always win
    if [ "$LG_NO_COLOR" -eq 1 ]; then
        lg_colors_disable
    elif [ "$LG_FORCE_COLOR" -eq 1 ]; then
        lg_colors_init
    fi

    # Resolve terminal width once so every renderer (including quiet mode)
    # has a valid LG_UI_COLS for rules, panels and truncation.
    lg_ui_init

    # Repair framework is only needed in fix mode
    if [ "$LG_MODE" = "fix" ]; then
        lg_load_core logger.sh
        lg_load_core backup.sh
        lg_load_core rollback.sh
        lg_load_core validator.sh
        lg_load_core repair_engine.sh
        lg_backup_init
        lg_log_init
    fi

    lg_load_config
    lg_platform_init
    lg_output_init
}
