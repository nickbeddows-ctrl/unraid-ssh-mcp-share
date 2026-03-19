"""
Unraid SSH MCP Server

A guardrailed MCP server that provides Docker management, file operations,
and system monitoring on an Unraid server via SSH. All commands pass through
safety validation before execution.
"""

import base64
import json
import re
import shlex
import logging
from typing import Optional, List

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

# --- Server & SSH Client ----------------------------------------------------

mcp = FastMCP(
    "unraid-ssh",
    instructions=(
        "Guardrailed SSH access to an Unraid server. Provides Docker management "
        "(exec, logs, inspect, lifecycle, build, run), host file operations "
        "(read/write/append with path restrictions and pagination), and system "
        "monitoring. Dangerous commands are blocked."
    ),
)

ssh = SSHClient()


def _run(command: str, timeout: Optional[int] = None) -> str:
    """Execute a command via SSH and return formatted output."""
    try:
        stdout, stderr, code = ssh.execute(command, timeout=timeout)
    except SSHConnectionError as e:
        return f"SSH Connection Error: {e}"

    parts = []
    if stdout.strip():
        parts.append(truncate_output(stdout.strip(), "stdout"))
    if stderr.strip():
        parts.append(f"STDERR:\n{truncate_output(stderr.strip(), 'stderr')}")
    if code != 0:
        parts.append(f"Exit code: {code}")

    return "\n".join(parts) if parts else "(no output)"


# =============================================================================
#  DOCKER TOOLS
# =============================================================================


@mcp.tool()
def docker_exec(container: str, command: str) -> str:
    """
    Execute a command inside a Docker container.

    Args:
        container: Container name or ID (e.g. 'n8n', 'postgres16').
        command: The command to run inside the container.
    """
    try:
        container = sanitize_container_name(container)
        command = validate_container_command(command)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    safe_cmd = shlex.quote(command)
    return _run(f"docker exec {container} sh -c {safe_cmd}")


@mcp.tool()
def docker_exec_it(container: str, command: str) -> str:
    """
    Execute an interactive command inside a Docker container.

    Same as docker_exec but with -it flags for commands that need a pseudo-TTY.

    Args:
        container: Container name or ID.
        command: The command to run.
    """
    try:
        container = sanitize_container_name(container)
        command = validate_container_command(command)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    safe_cmd = shlex.quote(command)
    return _run(f"docker exec -it {container} sh -c {safe_cmd}")


@mcp.tool()
def docker_logs(container: str, lines: int = 100, since: Optional[str] = None) -> str:
    """
    View Docker container logs.

    Args:
        container: Container name or ID.
        lines: Number of lines from the end (default 100, max 5000).
        since: Only show logs since this time (e.g. '1h', '2024-01-01', '30m').
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    lines = max(1, min(lines, 5000))
    cmd = f"docker logs --tail {lines}"
    if since:
        cmd += f" --since {shlex.quote(since)}"
    cmd += f" {container}"
    return _run(cmd, timeout=15)


@mcp.tool()
def docker_inspect(container: str) -> str:
    """
    Get full Docker container details including env vars, ports, mounts, and health.

    Args:
        container: Container name or ID.
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    raw = _run(f"docker inspect {container}")

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
                "Networks": list(c.get("NetworkSettings", {}).get("Networks", {}).keys()),
                "RestartPolicy": c.get("HostConfig", {}).get("RestartPolicy", {}),
            }
            return json.dumps(sections, indent=2)
    except (json.JSONDecodeError, KeyError, IndexError):
        pass

    return raw


@mcp.tool()
def docker_ps(all_containers: bool = False) -> str:
    """
    List Docker containers with their status, ports, and image.

    Args:
        all_containers: If True, include stopped containers (docker ps -a).
    """
    flag = "-a " if all_containers else ""
    return _run(
        f"docker ps {flag}--format "
        "'table {{{{.Names}}}}\t{{{{.Status}}}}\t{{{{.Ports}}}}\t{{{{.Image}}}}'"
    )


@mcp.tool()
def docker_restart(container: str) -> str:
    """Restart a Docker container."""
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"Guardrail: {e}"
    return _run(f"docker restart {container}")


@mcp.tool()
def docker_start(container: str) -> str:
    """Start a stopped Docker container."""
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"Guardrail: {e}"
    return _run(f"docker start {container}")


@mcp.tool()
def docker_stop(container: str) -> str:
    """Stop a running Docker container."""
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"Guardrail: {e}"
    return _run(f"docker stop {container}")


@mcp.tool()
def docker_rm(container: str, force: bool = False) -> str:
    """
    Remove a Docker container.

    Args:
        container: Container name or ID.
        force: Force removal of a running container (docker rm -f).
    """
    try:
        container = sanitize_container_name(container)
    except GuardrailError as e:
        return f"Guardrail: {e}"
    flag = "-f " if force else ""
    return _run(f"docker rm {flag}{container}")


@mcp.tool()
def docker_stats() -> str:
    """Show live resource usage (CPU, memory, I/O) for all running containers."""
    return _run(
        "docker stats --no-stream --format "
        "'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}'"
    )


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
        direction: 'from' (container to host) or 'to' (host to container).
    """
    try:
        container = sanitize_container_name(container)
        sanitize_path(container_path)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    if direction == "from":
        try:
            validate_write_path(host_path)
        except GuardrailError as e:
            return f"Guardrail: {e}"
        cmd = f"docker cp {container}:{shlex.quote(container_path)} {shlex.quote(host_path)}"
    elif direction == "to":
        try:
            validate_read_path(host_path)
        except GuardrailError as e:
            return f"Guardrail: {e}"
        cmd = f"docker cp {shlex.quote(host_path)} {container}:{shlex.quote(container_path)}"
    else:
        return "direction must be 'from' or 'to'"

    return _run(cmd)


@mcp.tool()
def docker_build(tag: str, context_path: str, dockerfile: Optional[str] = None) -> str:
    """
    Build a Docker image from a Dockerfile.

    Step 1 of the standard Fraggell deploy sequence:
      1. docker_build(tag, context_path)
      2. docker_stop(container)
      3. docker_rm(container)
      4. docker_run(image, name, env_file, ports, volumes)

    Args:
        tag: Image tag (e.g. 'my-app' or 'my-app:latest').
        context_path: Path to the build context directory on the Unraid host.
        dockerfile: Optional path to a specific Dockerfile if not at context root.
    """
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.\-:/]*$', tag):
        return "Guardrail: Invalid image tag format."

    try:
        context_path = sanitize_path(context_path)
        if dockerfile:
            dockerfile = sanitize_path(dockerfile)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    cmd = f"docker build -t {shlex.quote(tag)} {shlex.quote(context_path)}"
    if dockerfile:
        cmd += f" -f {shlex.quote(dockerfile)}"

    return _run(cmd, timeout=300)


@mcp.tool()
def docker_run(
    image: str,
    name: str,
    env_file: Optional[str] = None,
    ports: Optional[List[str]] = None,
    volumes: Optional[List[str]] = None,
    restart: str = "unless-stopped",
    detach: bool = True,
) -> str:
    """
    Run a new Docker container from an image.

    Step 4 of the standard Fraggell deploy sequence:
      1. docker_build(tag, context_path)
      2. docker_stop(container)
      3. docker_rm(container)
      4. docker_run(image, name, env_file, ports, volumes)

    Args:
        image: Image name/tag to run (e.g. 'my-app').
        name: Container name to assign.
        env_file: Host path to a .env file (e.g. '/mnt/user/appdata/my-app/.env').
        ports: Port mappings (e.g. ['3000:3000', '8080:80']).
        volumes: Volume mounts (e.g. ['/mnt/user/appdata/my-app:/app/data']).
        restart: Restart policy: 'unless-stopped', 'always', 'no', 'on-failure'.
        detach: Run in background (-d). Defaults to True.
    """
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.\-:/]*$', image):
        return "Guardrail: Invalid image name."

    try:
        name = sanitize_container_name(name)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    valid_restart = {"unless-stopped", "always", "no", "on-failure"}
    if restart not in valid_restart:
        return f"Guardrail: Invalid restart policy '{restart}'. Choose from: {', '.join(valid_restart)}"

    if env_file:
        try:
            env_file = validate_read_path(env_file)
        except GuardrailError as e:
            return f"Guardrail (env_file): {e}"

    port_args = ""
    if ports:
        for p in ports:
            if not re.match(r'^\d+:\d+(/tcp|/udp)?$', p):
                return f"Guardrail: Invalid port mapping '{p}'. Expected HOST_PORT:CONTAINER_PORT"
        port_args = " ".join(f"-p {shlex.quote(p)}" for p in ports)

    volume_args = ""
    if volumes:
        for v in volumes:
            host_part = v.split(":", 1)[0]
            try:
                sanitize_path(host_part)
            except GuardrailError as e:
                return f"Guardrail (volume '{host_part}'): {e}"
        volume_args = " ".join(f"-v {shlex.quote(v)}" for v in volumes)

    cmd_parts = ["docker run"]
    if detach:
        cmd_parts.append("-d")
    cmd_parts.append(f"--name {shlex.quote(name)}")
    if env_file:
        cmd_parts.append(f"--env-file {shlex.quote(env_file)}")
    if port_args:
        cmd_parts.append(port_args)
    if volume_args:
        cmd_parts.append(volume_args)
    cmd_parts.append(f"--restart {restart}")
    cmd_parts.append(shlex.quote(image))

    return _run(" ".join(cmd_parts), timeout=60)


# =============================================================================
#  FILESYSTEM TOOLS (HOST)
# =============================================================================


@mcp.tool()
def read_file(
    path: str,
    tail_lines: Optional[int] = None,
    offset_lines: Optional[int] = None,
    length_lines: Optional[int] = None,
) -> str:
    """
    Read a file on the Unraid host.

    Three read modes:
      - Default: read the entire file (up to 512 KB output cap).
      - tail_lines: read the last N lines.
      - offset_lines + length_lines: read a specific line range for paginating
        large files. offset_lines is 0-based; length_lines defaults to 200.

    Args:
        path: Absolute file path.
        tail_lines: Return only the last N lines (max 5000).
        offset_lines: Start reading from this line number (0-based).
        length_lines: Lines to read when using offset_lines (max 2000, default 200).
    """
    try:
        path = validate_read_path(path)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    if tail_lines and tail_lines > 0:
        cmd = f"tail -n {min(tail_lines, 5000)} {shlex.quote(path)}"
    elif offset_lines is not None:
        start = max(1, offset_lines + 1)  # sed is 1-indexed
        n = min(length_lines or 200, 2000)
        end = start + n - 1
        cmd = f"sed -n '{start},{end}p' {shlex.quote(path)}"
    else:
        cmd = f"cat {shlex.quote(path)}"

    return _run(cmd)


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """
    Write content to a file on the Unraid host.

    Only allowed in: /mnt/user, /mnt/cache, /mnt/disk, /tmp.

    Uses base64 encoding so any file content (special characters, escape
    sequences, delimiter strings) is transferred safely without corruption.

    For large files: use write_file for chunk 1, then append_file for the rest.

    Args:
        path: Absolute file path.
        content: Content to write.
    """
    try:
        path = validate_write_path(path)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    cmd = f"echo {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}"
    return _run(cmd)


@mcp.tool()
def append_file(path: str, content: str) -> str:
    """
    Append content to an existing file on the Unraid host.

    Use with write_file for chunked writes of large files:
      1. write_file(path, chunk1)   -- creates/overwrites
      2. append_file(path, chunk2)  -- appends
      3. append_file(path, chunk3)  -- continues

    Uses base64 encoding for safe transfer of any content.

    Args:
        path: Absolute file path.
        content: Content to append.
    """
    try:
        path = validate_write_path(path)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    cmd = f"echo {shlex.quote(encoded)} | base64 -d >> {shlex.quote(path)}"
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
        return f"Guardrail: {e}"

    flags = "-la" if show_hidden else "-l"
    return _run(f"ls {flags} {shlex.quote(path)}")


@mcp.tool()
def create_directory(path: str) -> str:
    """
    Create a directory (and any missing parents) on the Unraid host.

    Equivalent to mkdir -p. Only allowed under /mnt/user, /mnt/cache,
    /mnt/disk, or /tmp.

    Args:
        path: Absolute path of the directory to create.
    """
    try:
        path = validate_write_path(path)
    except GuardrailError as e:
        return f"Guardrail: {e}"
    return _run(f"mkdir -p {shlex.quote(path)}")


@mcp.tool()
def find_files(path: str, name_pattern: str, max_depth: int = 3) -> str:
    """
    Search for files on the Unraid host.

    Args:
        path: Directory to search in.
        name_pattern: Filename pattern (supports wildcards, e.g. '*.conf').
        max_depth: Maximum directory depth to search (default 3, max 10).
    """
    try:
        path = sanitize_path(path)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    max_depth = max(1, min(max_depth, 10))
    return _run(
        f"find {shlex.quote(path)} -maxdepth {max_depth} "
        f"-name {shlex.quote(name_pattern)} 2>/dev/null | head -100"
    )


# =============================================================================
#  SYSTEM TOOLS
# =============================================================================


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
        output.append(f"-- {label} --\n{result}")
    return "\n\n".join(output)


@mcp.tool()
def run_command(command: str) -> str:
    """
    Run a command on the Unraid host with guardrails.

    Dangerous commands (rm, dd, shutdown, mount, passwd, etc.) are blocked.

    Args:
        command: The shell command to run.

    Examples:
        run_command("ip addr")
        run_command("docker network ls")
        run_command("ls -la /mnt/user/appdata/n8n")
    """
    try:
        command = validate_host_command(command)
    except GuardrailError as e:
        return f"Guardrail: {e}"
    return _run(command)


@mcp.tool()
def tail_log(log_path: str, lines: int = 100) -> str:
    """
    Tail a log file on the Unraid host.

    Args:
        log_path: Absolute path to the log file.
        lines: Number of lines from the end (default 100, max 5000).
    """
    try:
        log_path = validate_read_path(log_path)
    except GuardrailError as e:
        return f"Guardrail: {e}"

    lines = max(1, min(lines, 5000))
    return _run(f"tail -n {lines} {shlex.quote(log_path)}")


# =============================================================================
#  ENTRY POINT
# =============================================================================


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
