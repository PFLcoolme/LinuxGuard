#!/bin/sh
# modules/packages.sh - Package and update status audit module

lg_run_packages() {
    if [ "$LG_PACKAGE_MANAGER" = "unknown" ]; then
        lg_finding \
            "UNKNOWN" \
            "Packages & Updates / 软件包与更新" \
            "PACKAGE_MANAGER" \
            "No supported package manager detected / 未检测到支持的包管理器" \
            "Unknown / 未知" \
            "Unknown package manager / 未知包管理器" \
            "Cannot determine update status / 无法确定更新状态。" \
            "Review vendor security advisories manually / 请手动查看厂商安全公告。"
        return
    fi

    case "$LG_PACKAGE_MANAGER" in
        apt)
            if lg_command_exists apt-get; then
                lg_finding \
                    "UNKNOWN" \
                    "Packages & Updates / 软件包与更新" \
                    "PACKAGE_UPDATES" \
                    "APT update status not queried / 未查询 APT 更新状态" \
                    "Unknown / 未知" \
                    "No package index refresh performed / 未刷新软件包索引" \
                    "LinuxGuard does not run apt update/upgrade to avoid modifying the system / LinuxGuard 不运行 apt update/upgrade 以避免修改系统。" \
                    "Run your distribution's trusted update workflow and review security advisories / 运行发行版可信的更新流程并查看安全公告。"
            else
                lg_finding \
                    "UNKNOWN" \
                    "Packages & Updates / 软件包与更新" \
                    "PACKAGE_TOOLING" \
                    "APT tooling unavailable / APT 工具不可用" \
                    "Unknown / 未知" \
                    "apt-get not found / 未找到 apt-get" \
                    "Cannot check package status / 无法检查软件包状态。" \
                    "Install apt or review manually / 安装 apt 或手动检查。"
            fi
            ;;
        pacman)
            lg_finding \
                "UNKNOWN" \
                "Packages & Updates / 软件包与更新" \
                "PACKAGE_UPDATES" \
                "Package vulnerability status not determined / 未确定软件包漏洞状态" \
                "Unknown / 未知" \
                "Arch package updates require repository metadata / Arch 软件包更新需要仓库元数据" \
                "Review official Arch security announcements and update status / 查看官方 Arch 安全公告和更新状态。" \
                "Run pacman -Syu through your trusted maintenance window / 在可信维护窗口运行 pacman -Syu。"
            ;;
        dnf|yum)
            lg_finding \
                "UNKNOWN" \
                "Packages & Updates / 软件包与更新" \
                "PACKAGE_UPDATES" \
                "Package vulnerability status not determined / 未确定软件包漏洞状态" \
                "Unknown / 未知" \
                "No repository query performed / 未查询仓库" \
                "Review vendor security advisories and update status / 查看厂商安全公告和更新状态。" \
                "Run dnf/yum update through your trusted maintenance window / 在可信维护窗口运行 dnf/yum update。"
            ;;
        apk)
            lg_finding \
                "UNKNOWN" \
                "Packages & Updates / 软件包与更新" \
                "PACKAGE_UPDATES" \
                "Package vulnerability status not determined / 未确定软件包漏洞状态" \
                "Unknown / 未知" \
                "No repository query performed / 未查询仓库" \
                "Review Alpine security advisories and update status / 查看 Alpine 安全公告和更新状态。" \
                "Run apk upgrade through your trusted maintenance window / 在可信维护窗口运行 apk upgrade。"
            ;;
        *)
            lg_finding \
                "UNKNOWN" \
                "Packages & Updates / 软件包与更新" \
                "PACKAGE_UPDATES" \
                "Unsupported package manager family / 不支持的包管理器系列" \
                "Unknown / 未知" \
                "${LG_PACKAGE_MANAGER}" \
                "Cannot determine update status for this package manager / 无法确定此包管理器的更新状态。" \
                "Review vendor security advisories manually / 请手动查看厂商安全公告。"
            ;;
    esac
}
