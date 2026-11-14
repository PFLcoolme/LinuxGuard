#!/bin/sh
# repairs/docker_repair.sh - Docker security repairs

lg_repair_docker_socket() {
    if [ -e /var/run/docker.sock ]; then
        printf '  Setting /var/run/docker.sock permissions to 660 / 设置 /var/run/docker.sock 权限为 660\n'
        chmod 660 /var/run/docker.sock 2>/dev/null
    else
        printf '  Docker socket not found / 未找到 Docker socket\n'
        return 1
    fi
}
