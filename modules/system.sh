#!/bin/sh
# modules/system.sh - System information and privilege detection

lg_run_system() {
    lg_finding \
        "PASS" \
        "System Information / 系统信息" \
        "OS_DETECTED" \
        "Operating system detected / 操作系统已识别" \
        "Detected / 已识别" \
        "${LG_OS_NAME} ${LG_OS_VERSION} (${LG_OS_ID})" \
        "System environment identified for audit context / 系统环境已识别，用于审计上下文。" \
        "No action required / 无需操作。"

    lg_finding \
        "PASS" \
        "System Information / 系统信息" \
        "KERNEL_VERSION" \
        "Kernel version / 内核版本" \
        "Detected / 已识别" \
        "${LG_KERNEL}" \
        "Ensure kernel is supported and patched / 确保内核受支持并已打补丁。" \
        "Apply vendor security updates regularly / 定期应用厂商安全更新。"

    lg_finding \
        "PASS" \
        "System Information / 系统信息" \
        "ARCHITECTURE" \
        "System architecture / 系统架构" \
        "Detected / 已识别" \
        "${LG_ARCH}" \
        "Architecture identified / 架构已识别。" \
        "No action required / 无需操作。"

    if lg_is_root; then
        lg_finding \
            "PASS" \
            "System Information / 系统信息" \
            "PRIVILEGE_LEVEL" \
            "Audit running as root / 以 root 身份运行审计" \
            "Running as root / 以 root 运行" \
            "User ID 0 / 用户 ID 0" \
            "Running with root privileges allows full audit coverage / 以 root 权限运行可实现完整审计覆盖。" \
            "No action required / 无需操作。"
    else
        lg_finding \
            "LOW" \
            "System Information / 系统信息" \
            "PRIVILEGE_LEVEL" \
            "Audit running as non-root user / 以非 root 用户运行审计" \
            "Limited / 受限" \
            "User ID $(id -u) / 用户 ID $(id -u)" \
            "Some checks may be incomplete / 部分检查可能不完整。" \
            "Re-run as root for complete results if permitted / 如允许，请以 root 重新运行以获得完整结果。"
    fi

    _pkg_status="Detected / 已识别"
    if [ "$LG_PACKAGE_MANAGER" = "unknown" ]; then
        _pkg_status="Not detected / 未识别"
    fi
    lg_finding \
        "PASS" \
        "System Information / 系统信息" \
        "PACKAGE_MANAGER" \
        "Package manager detected / 包管理器已识别" \
        "Detected / 已识别" \
        "${LG_PACKAGE_MANAGER} (${_pkg_status})" \
        "Package manager identified for update checks / 包管理器已识别，用于更新检查。" \
        "No action required / 无需操作。"
}
