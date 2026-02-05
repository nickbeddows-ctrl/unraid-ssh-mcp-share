"""
Guardrails for Unraid SSH MCP Server.

Validates commands, paths, and container names to prevent dangerous operations
on the Unraid host. Docker exec commands inside containers are more permissive
since they're isolated from the host.
"""

import re
import shlex


# ─── Host Command Blocklist ──────────────────────────────────────────────────
# These commands are NEVER allowed to run directly on the Unraid host.

BLOCKED_HOST_COMMANDS = {
    # Destructive file operations
    "rm", "rmdir", "shred", "wipe", "srm",
    # Disk / partition / filesystem
    "dd", "mkfs", "fdisk", "gdisk", "parted", "mdadm",
    "mkswap", "swapon", "swapoff",
    "mount", "umount",
    # System power
    "shutdown", "reboot", "poweroff", "halt", "init",
    # Firewall / networking changes
    "iptables", "ip6tables", "nftables", "firewall-cmd",
    # User / auth management
    "passwd", "useradd", "userdel", "usermod",
    "groupadd", "groupdel", "groupmod",
    # Unraid package management
    "installpkg", "removepkg", "upgradepkg", "slackpkg",
    # Permission changes on host
    "chmod", "chown", "chgrp",
    # Scheduled tasks
    "crontab", "at",
    # Dangerous built-ins / utilities
    "eval", "exec", "source",
    "nohup", "screen", "tmux",
}

# ─── Blocked Patterns ────────────────────────────────────────────────────────
# Regex patterns blocked in ANY command (host or container).

BLOCKED_PATTERNS = [
    (r">\s*/dev/", "Redirecting output to a device"),
    (r">\s*/boot/", "Writing to Unraid flash drive (/boot)"),
    (r":\(\)\s*\{", "Fork bomb detected"),
    (r"\brm\s+.*-[^\s]*r[^\s]*f", "rm with -rf flags"),
    (r"\brm\s+.*-[^\s]*f[^\s]*r", "rm with -fr flags"),
]

# Additional patterns only blocked on the HOST (not inside containers).
BLOCKED_HOST_PATTERNS = [
    (r">\s*/etc/", "Writing to /etc on host"),
    (r">\s*/usr/", "Writing to /usr on host"),
    (r"\|.*\b(rm|dd|mkfs)\b", "Piping to destructive command"),
]

# ─── Path Restrictions ───────────────────────────────────────────────────────

BLOCKED_READ_PATHS = [
    "/boot/config/shadow",
    "/boot/config/smbpasswd",
    "/etc/shadow",
    "/etc/gshadow",
]

BLOCKED_WRITE_PATHS = [
    "/boot",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/dev",
    "/proc",
    "/sys",
]

ALLOWED_WRITE_PATHS = [
    "/mnt/user",
    "/mnt/cache",
    "/mnt/disk",
    "/tmp",
]

# ─── Validation Patterns ─────────────────────────────────────────────────────

CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$")
SAFE_PATH_RE = re.compile(r"^[a-zA-Z0-9/_.\-\s\+\@\:]+$")


class GuardrailError(Exception):
    """Raised when a command or path fails guardrail validation."""
    pass


# ─── Input Sanitisation ─────────────────────────────────────────────────────

def sanitize_container_name(name: str) -> str:
    """Validate and return a safe Docker container name or ID."""
    name = name.strip()
    if not name:
        raise GuardrailError("Container name cannot be empty.")
    if not CONTAINER_NAME_RE.match(name):
        raise GuardrailError(
            f"Invalid container name: '{name}'. "
            "Only alphanumeric characters, hyphens, underscores, and dots are allowed."
        )
    return name


def sanitize_path(path: str) -> str:
    """Validate a file path contains no traversal or injection."""
    path = path.strip()
    if not path:
        raise GuardrailError("Path cannot be empty.")
    if ".." in path:
        raise GuardrailError("Path traversal ('..') is not allowed.")
    if not path.startswith("/"):
        raise GuardrailError("Path must be absolute (start with '/').")
    if not SAFE_PATH_RE.match(path):
        raise GuardrailError(f"Path contains disallowed characters: '{path}'")
    return path


# ─── Command Validation ─────────────────────────────────────────────────────

def validate_host_command(command: str) -> str:
    """
    Validate a command intended for the Unraid HOST.
    Raises GuardrailError if the command is dangerous.
    """
    command = command.strip()
    if not command:
        raise GuardrailError("Command cannot be empty.")

    try:
        parts = shlex.split(command)
    except ValueError:
        raise GuardrailError("Command has malformed quoting.")

    base_cmd = parts[0].split("/")[-1]

    if base_cmd in BLOCKED_HOST_COMMANDS:
        raise GuardrailError(
            f"🚫 Command '{base_cmd}' is blocked on the Unraid host. "
            "This command could damage the system."
        )

    for pattern, description in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            raise GuardrailError(f"🚫 Blocked: {description}")

    for pattern, description in BLOCKED_HOST_PATTERNS:
        if re.search(pattern, command):
            raise GuardrailError(f"🚫 Blocked on host: {description}")

    return command


def validate_container_command(command: str) -> str:
    """
    Validate a command intended for INSIDE a Docker container.
    More permissive than host commands since containers are isolated.
    """
    command = command.strip()
    if not command:
        raise GuardrailError("Command cannot be empty.")

    for pattern, description in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            raise GuardrailError(f"🚫 Blocked: {description}")

    return command


def validate_read_path(path: str) -> str:
    """Validate a path is safe to read from."""
    path = sanitize_path(path)
    for blocked in BLOCKED_READ_PATHS:
        if path == blocked or path.startswith(blocked + "/"):
            raise GuardrailError(f"🚫 Reading '{path}' is not allowed (sensitive file).")
    return path


def validate_write_path(path: str) -> str:
    """Validate a path is safe to write to."""
    path = sanitize_path(path)

    for blocked in BLOCKED_WRITE_PATHS:
        if path == blocked or path.startswith(blocked + "/"):
            raise GuardrailError(f"🚫 Writing to '{path}' is blocked (system path).")

    allowed = any(
        path == ap or path.startswith(ap + "/")
        for ap in ALLOWED_WRITE_PATHS
    )
    if not allowed:
        raise GuardrailError(
            f"🚫 Writing to '{path}' is not allowed.\n"
            f"Allowed locations: {', '.join(ALLOWED_WRITE_PATHS)}"
        )

    return path


# ─── Output Limits ───────────────────────────────────────────────────────────

MAX_OUTPUT_BYTES = 64 * 1024  # 64 KB


def truncate_output(text: str, label: str = "output") -> str:
    """Truncate output if it exceeds the size limit."""
    if len(text.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        half = MAX_OUTPUT_BYTES // 2
        head = text[:half]
        tail = text[-half:]
        return (
            f"{head}\n\n"
            f"⚠️  {label} truncated ({len(text):,} chars total). "
            f"Showing first and last ~{half:,} bytes.\n\n"
            f"{tail}"
        )
    return text
