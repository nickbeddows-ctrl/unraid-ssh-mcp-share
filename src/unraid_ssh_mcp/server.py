"""
Unraid SSH MCP Server

A guardrailed MCP server that provides Docker management, file operations,
and system monitoring on an Unraid server via SSH. All commands pass through
safety validation before execution.
"""

import json
import shlex
import logging
from typing import Optional

from dotenv import load_dotenv
from fastmcp import FastMCP

from .ssh_client import SSHClient, SSHConnectionError
from .guardrails import (
    GuardrailError,
    sanitize_container_name,
    validate_host_command,
    validate_container_command,
    validate_read_path,
    validate_write_path,
    sanitize_path,
    truncate_output,
)

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("unraid-ssh-mcp")

# ─── Server & SSH Client ────────────────────────────────────────────────────

mcp = FastMCP(
    "unraid-ssh",
    instructions=(
        "Guardrailed SSH access to an Unraid server. Provides Docker management "
        "(exec, logs, inspect, lifecycle), host file operations (read/write with "
        "path restrictions), and system monitoring. Dangerous commands are blocked."
    ),
)

ssh = SSHClient()


def _run(command: str, timeout: Optional[int] = None) -> str:
    """Execute a command via SSH and return formatted output."""
    try:
        stdout, stderr, code = ssh.execute(command, timeout=timeout)
    except SSHConnectionError as e:
        return f"❌ SSH Connection Error: {e}"

    parts = []
    if stdout.strip():
        parts.append(truncate_output(stdout.strip(), "stdout"))
    if stderr.strip():
        parts.append(f"STDERR:\n{truncate_output(stderr.strip(), 'stderr')}")
    if code != 0:
        parts.append(f"Exit code: {code}")

    return "\n".join(parts) if parts else "(no output)"


# ═══════════════════════════════════════════════════════════════════════════════
#  DOCKER TOOLS
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def docker_exec(container: str, command: str) -> str:
    """
    Execute a command inside a Docker container.

    This runs the command in the container's environment, not on the host.
    Most commands are allowed since containers are isolated.

    Args:
        container: Container name or ID (e.g. 'n8n', 'postgres16').
        command: The command to run inside the container.

    Examples:
        docker_exec("n8n", "ls /home/node")
        docker_exec("postgres16", "psql -U postgres -c 'SELECT version()'")
        docker_exec("n8n", "env")  # View environment variables
    """
    try:
        container = sanitize_container_name(container)
        command = validate_container_command(command)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    safe_cmd = shlex.quote(command)
    return _run(f"docker exec {container} sh -c {safe_cmd}")


@mcp.tool()
def docker_exec_it(container: str, command: str) -> str:
    """
    Execute an interactive command inside a Docker container.

    Same as docker_exec but with -it flags, useful for commands that
    need a pseudo-TTY (e.g. some database CLIs).

    Args:
        container: Container name or ID.
        command: The command to run.
    """
    try:
        container = sanitize_container_name(container)
        command = validate_container_command(command)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    safe_cmd = shlex.quote(command)
    return _run(f"docker exec -it {container} sh -c {safe_cmd}")


@mcp.tool()
def docker_logs(container: str, lines: int = 100, since: Optional[str] = None) -> str:
    """
    View Docker container logs.

    Args:
        container: Container name or ID.
        lines: Number of lines from the end (default 100).
        since: Only show logs since this time (e.g. '1h', '2024-01-01', '30m').
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    lines = max(1, min(lines, 5000))
    cmd = f"docker logs --tail {lines}"
    if since:
        cmd += f" --since {shlex.quote(since)}"
    cmd += f" {container}"
    return _run(cmd, timeout=15)


@mcp.tool()
def docker_inspect(container: str) -> str:
    """
    Get full Docker container details including environment variables,
    port mappings, mounts, network settings, and health status.

    ⚠️  Output may include sensitive values (passwords, API keys) from
    container environment variables.

    Args:
        container: Container name or ID.
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    raw = _run(f"docker inspect {container}")

    # Try to pretty-format key sections
    try:
        data = json.loads(raw)
        if isinstance(data, list) and len(data) > 0:
            c = data[0]
            sections = {
                "Name": c.get("Name", ""),
                "State": c.get("State", {}),
                "Image": c.get("Config", {}).get("Image", ""),
                "Env": c.get("Config", {}).get("Env", []),
                "Ports": c.get("NetworkSettings", {}).get("Ports", {}),
                "Mounts": [
                    {
                        "Source": m.get("Source"),
                        "Destination": m.get("Destination"),
                        "Mode": m.get("Mode"),
                    }
                    for m in c.get("Mounts", [])
                ],
                "Networks": list(
                    c.get("NetworkSettings", {}).get("Networks", {}).keys()
                ),
                "RestartPolicy": c.get("HostConfig", {}).get("RestartPolicy", {}),
            }
            return json.dumps(sections, indent=2)
    except (json.JSONDecodeError, KeyError, IndexError):
        pass

    return raw


@mcp.tool()
def docker_restart(container: str) -> str:
    """
    Restart a Docker container.

    Args:
        container: Container name or ID.
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    return _run(f"docker restart {container}")


@mcp.tool()
def docker_start(container: str) -> str:
    """
    Start a stopped Docker container.

    Args:
        container: Container name or ID.
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    return _run(f"docker start {container}")


@mcp.tool()
def docker_stop(container: str) -> str:
    """
    Stop a running Docker container.

    Args:
        container: Container name or ID.
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    return _run(f"docker stop {container}")


@mcp.tool()
def docker_stats() -> str:
    """
    Show live resource usage for all running containers.
    Returns CPU %, memory usage, network I/O, and block I/O.
    """
    return _run("docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}'")


@mcp.tool()
def docker_cp(
    container: str,
    container_path: str,
    host_path: str,
    direction: str = "from",
) -> str:
    """
    Copy files between a container and the host.

    Args:
        container: Container name or ID.
        container_path: Path inside the container.
        host_path: Path on the Unraid host.
        direction: 'from' (container→host) or 'to' (host→container).
    """
    try:
        container = sanitize_container_name(container)
        sanitize_path(container_path)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    if direction == "from":
        # Copying FROM container TO host — validate the host destination
        try:
            validate_write_path(host_path)
        except GuardrailError as e:
            return f"⚠️ Guardrail: {e}"
        cmd = f"docker cp {container}:{shlex.quote(container_path)} {shlex.quote(host_path)}"
    elif direction == "to":
        # Copying FROM host TO container — validate the host source is readable
        try:
            validate_read_path(host_path)
        except GuardrailError as e:
            return f"⚠️ Guardrail: {e}"
        cmd = f"docker cp {shlex.quote(host_path)} {container}:{shlex.quote(container_path)}"
    else:
        return "⚠️ direction must be 'from' or 'to'"

    return _run(cmd)


# ═══════════════════════════════════════════════════════════════════════════════
#  FILESYSTEM TOOLS (HOST)
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def read_file(path: str, tail_lines: Optional[int] = None) -> str:
    """
    Read a file on the Unraid host.

    Blocked from reading sensitive files (shadow, smbpasswd, etc.).

    Args:
        path: Absolute file path.
        tail_lines: If set, only return the last N lines.
    """
    try:
        path = validate_read_path(path)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    if tail_lines and tail_lines > 0:
        cmd = f"tail -n {min(tail_lines, 5000)} {shlex.quote(path)}"
    else:
        cmd = f"cat {shlex.quote(path)}"

    return _run(cmd)


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """
    Write content to a file on the Unraid host.

    Only allowed in specific directories: /mnt/user, /mnt/cache, /mnt/disk, /tmp.
    Cannot write to system paths (/boot, /etc, /usr, etc.).

    Args:
        path: Absolute file path.
        content: Content to write.
    """
    try:
        path = validate_write_path(path)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    # Use heredoc to write content safely
    safe_path = shlex.quote(path)
    # Escape any EOF-like strings in content
    delimiter = "_UNRAID_SSH_MCP_EOF_"
    cmd = f"cat > {safe_path} << '{delimiter}'\n{content}\n{delimiter}"

    return _run(cmd)


@mcp.tool()
def list_directory(path: str, show_hidden: bool = False) -> str:
    """
    List contents of a directory on the Unraid host.

    Args:
        path: Absolute directory path.
        show_hidden: Include hidden files (dotfiles).
    """
    try:
        path = sanitize_path(path)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    flags = "-la" if show_hidden else "-l"
    return _run(f"ls {flags} {shlex.quote(path)}")


@mcp.tool()
def find_files(path: str, name_pattern: str, max_depth: int = 3) -> str:
    """
    Search for files on the Unraid host.

    Args:
        path: Directory to search in.
        name_pattern: Filename pattern (supports wildcards, e.g. '*.conf').
        max_depth: Maximum directory depth to search (default 3).
    """
    try:
        path = sanitize_path(path)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    max_depth = max(1, min(max_depth, 10))
    return _run(
        f"find {shlex.quote(path)} -maxdepth {max_depth} -name {shlex.quote(name_pattern)} 2>/dev/null | head -100"
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  SYSTEM TOOLS
# ═══════════════════════════════════════════════════════════════════════════════


@mcp.tool()
def system_overview() -> str:
    """
    Quick overview of the Unraid system: uptime, CPU load, memory, disk usage,
    and top processes by CPU.
    """
    commands = [
        ("Hostname", "hostname"),
        ("Uptime", "uptime"),
        ("Memory", "free -h"),
        ("Disk Usage", "df -h | grep -E '^/dev|^shm|Filesystem'"),
        ("CPU Load", "cat /proc/loadavg"),
        ("Top Processes", "ps aux --sort=-%cpu | head -10"),
    ]
    output = []
    for label, cmd in commands:
        result = _run(cmd, timeout=10)
        output.append(f"── {label} ──\n{result}")
    return "\n\n".join(output)


@mcp.tool()
def run_command(command: str) -> str:
    """
    Run a command on the Unraid host with guardrails.

    Dangerous commands (rm, dd, shutdown, mount, passwd, etc.) are blocked.
    Use this for general system queries, diagnostics, and monitoring.

    Args:
        command: The shell command to run.

    Examples:
        run_command("ip addr")
        run_command("smartctl -a /dev/nvme0n1")
        run_command("cat /proc/mdstat")
        run_command("docker network ls")
        run_command("ls -la /mnt/user/appdata/n8n")
    """
    try:
        command = validate_host_command(command)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    return _run(command)


@mcp.tool()
def tail_log(log_path: str, lines: int = 100) -> str:
    """
    Tail a log file on the Unraid host.

    Common log paths:
      /var/log/syslog — system log
      /var/log/docker.log — Docker daemon log

    Args:
        log_path: Absolute path to the log file.
        lines: Number of lines from the end (default 100, max 5000).
    """
    try:
        log_path = validate_read_path(log_path)
    except GuardrailError as e:
        return f"⚠️ Guardrail: {e}"

    lines = max(1, min(lines, 5000))
    return _run(f"tail -n {lines} {shlex.quote(log_path)}")


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
