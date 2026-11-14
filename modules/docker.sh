#!/bin/sh
# modules/docker.sh - Docker security audit module

lg_run_docker() {
    if ! lg_command_exists docker; then
        lg_finding \
            "SKIP" \
            "Docker Security / Docker 安全" \
            "DOCKER_NOT_INSTALLED" \
            "Docker CLI not detected / 未检测到 Docker CLI" \
            "Skipped / 跳过" \
            "docker not in PATH / docker 不在 PATH 中" \
            "Docker does not appear to be installed / Docker 似乎未安装。" \
            "No action required / 无需操作。"
        return
    fi

    if docker info >/dev/null 2>&1; then
        lg_finding \
            "PASS" \
            "Docker Security / Docker 安全" \
            "DOCKER_DAEMON" \
            "Docker daemon is accessible / Docker 守护进程可访问" \
            "Compliant / 合规" \
            "Docker is installed and responding / Docker 已安装并响应" \
            "Review privileged containers, exposed sockets, and published ports / 检查特权容器、暴露的 socket 和发布端口。" \
            "Run docker ps and inspect container configurations / 运行 docker ps 并检查容器配置。"

        # Privileged containers
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q .; then
            _priv=$(docker ps --format '{{.Names}}' --filter 'expose=privileged' 2>/dev/null)
            if [ -z "$_priv" ]; then
                # Try alternative check via inspect
                _priv=$(docker ps -q 2>/dev/null | while IFS= read -r _cid; do
                    if docker inspect --format '{{.HostConfig.Privileged}}' "$_cid" 2>/dev/null | grep -qx 'true'; then
                        docker inspect --format '{{.Name}}' "$_cid" 2>/dev/null | sed 's|^/||'
                    fi
                done | tr '\n' ' ' | sed 's/ $//')
            fi

            if [ -n "$_priv" ]; then
                lg_finding \
                    "HIGH" \
                    "Docker Security / Docker 安全" \
                    "DOCKER_PRIVILEGED" \
                    "Privileged containers are running / 正在运行特权容器" \
                    "Risk found / 发现风险" \
                    "${_priv}" \
                    "Privileged containers have full host access and bypass most container isolation / 特权容器拥有完整主机访问权限并绕过大部分容器隔离。" \
                    "Recreate containers without --privileged unless strictly required / 除非严格需要，否则重建容器时不使用 --privileged。"
            else
                lg_finding \
                    "PASS" \
                    "Docker Security / Docker 安全" \
                    "DOCKER_PRIVILEGED" \
                    "No privileged containers detected / 未检测到特权容器" \
                    "Compliant / 合规" \
                    "No containers with HostConfig.Privileged=true / 无 HostConfig.Privileged=true 的容器" \
                    "No privileged containers found / 未发现特权容器。" \
                    "No action required / 无需操作。"
            fi

            # Published ports
            _ports=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:' | head -n 5)
            if [ -n "$_ports" ]; then
                lg_finding \
                    "MEDIUM" \
                    "Docker Security / Docker 安全" \
                    "DOCKER_PUBLISHED_PORTS" \
                    "Containers publish ports on host interfaces / 容器在主机接口上发布端口" \
                    "Risk found / 发现风险" \
                    "${_ports}" \
                    "Published container ports may bypass the host firewall / 发布的容器端口可能绕过主机防火墙。" \
                    "Bind to 127.0.0.1 or restrict via firewall when possible / 如可能，绑定到 127.0.0.1 或通过防火墙限制。"
            else
                lg_finding \
                    "PASS" \
                    "Docker Security / Docker 安全" \
                    "DOCKER_PUBLISHED_PORTS" \
                    "No publicly published container ports detected / 未检测到公开发布的容器端口" \
                    "Compliant / 合规" \
                    "No 0.0.0.0 bindings found / 未找到 0.0.0.0 绑定" \
                    "No container ports are published on all interfaces / 未在所有接口上发布容器端口。" \
                    "No action required / 无需操作。"
            fi
        else
            lg_finding \
                "PASS" \
                "Docker Security / Docker 安全" \
                "DOCKER_CONTAINERS" \
                "No running containers / 无运行中的容器" \
                "Compliant / 合规" \
                "docker ps returned empty / docker ps 返回为空" \
                "No containers are currently running / 当前没有运行中的容器。" \
                "No action required / 无需操作。"
        fi

        # Docker socket permissions
        if [ -e /var/run/docker.sock ]; then
            _sock_mode=$(lg_file_mode /var/run/docker.sock)
            if [ -n "$_sock_mode" ] && [ "$_sock_mode" -le 660 ]; then
                lg_finding \
                    "PASS" \
                    "Docker Security / Docker 安全" \
                    "DOCKER_SOCKET" \
                    "Docker socket permissions are restrictive / Docker socket 权限受限" \
                    "Compliant / 合规" \
                    "mode=${_sock_mode}" \
                    "The Docker socket is not world-writable / Docker socket 不可被全局写入。" \
                    "No action required / 无需操作。"
            else
                lg_finding \
                    "HIGH" \
                    "Docker Security / Docker 安全" \
                    "DOCKER_SOCKET" \
                    "Docker socket permissions are too permissive / Docker socket 权限过于宽松" \
                    "Risk found / 发现风险" \
                    "mode=${_sock_mode:-unknown}" \
                    "World-writable Docker socket grants passwordless root equivalent access / 全局可写的 Docker socket 等同于无密码 root 访问。" \
                    "Restrict /var/run/docker.sock to root and docker group / 将 /var/run/docker.sock 限制为 root 和 docker 组。"
            fi
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "Docker Security / Docker 安全" \
            "DOCKER_DAEMON" \
            "Docker CLI exists but daemon status unavailable / Docker CLI 存在但守护进程状态不可用" \
            "Unknown / 未知" \
            "docker info failed / docker info 失败" \
            "Check Docker service and permissions / 检查 Docker 服务和权限。" \
            "Run as root or a user in the docker group / 请以 root 或 docker 组成员用户运行。"
    fi
}
