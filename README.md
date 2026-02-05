# unraid-ssh-mcp

A **guardrailed** MCP server that gives Claude (or any MCP client) SSH access to an Unraid server — with safety controls built in.

Instead of exposing a raw shell, the server provides purpose-built tools for Docker management, file operations, and system monitoring. Dangerous commands are blocked before they ever reach the server.

## Why?

The official [unraid-mcp](https://github.com/chrisbenincasa/unraid-mcp) server uses the GraphQL API and covers array health, disk status, and basic container start/stop — but it **can't** run `docker exec`, view container environment variables, read log files, or edit configs.

This server fills that gap via SSH, with guardrails so Claude can't accidentally `rm -rf /` your flash drive.

---

## Features

### Docker Tools
| Tool | Description |
|------|-------------|
| `docker_exec` | Run a command inside a container |
| `docker_exec_it` | Run an interactive command (with pseudo-TTY) |
| `docker_logs` | View container logs (with tail/since) |
| `docker_inspect` | Full container details including env vars, ports, mounts |
| `docker_start` | Start a stopped container |
| `docker_stop` | Stop a running container |
| `docker_restart` | Restart a container |
| `docker_stats` | Live resource usage for all containers |
| `docker_cp` | Copy files between container and host |

### Filesystem Tools
| Tool | Description |
|------|-------------|
| `read_file` | Read a file (blocked from sensitive paths) |
| `write_file` | Write to allowed paths only (`/mnt/user`, `/tmp`, etc.) |
| `list_directory` | List directory contents |
| `find_files` | Search for files by name pattern |

### System Tools
| Tool | Description |
|------|-------------|
| `system_overview` | Uptime, CPU, memory, disk usage, top processes |
| `run_command` | General command with full guardrails |
| `tail_log` | Tail a log file |

---

## Security Model

### Blocked on Host
These commands are **never** executed on the Unraid host:

- **Destructive**: `rm`, `rmdir`, `shred`, `dd`, `mkfs`
- **System power**: `shutdown`, `reboot`, `poweroff`, `halt`
- **Firewall**: `iptables`, `ip6tables`, `nftables`
- **User mgmt**: `passwd`, `useradd`, `userdel`
- **Packages**: `installpkg`, `removepkg`, `slackpkg`
- **Permissions**: `chmod`, `chown`, `chgrp`
- **Disk ops**: `fdisk`, `parted`, `mdadm`, `mount`, `umount`

### Blocked Patterns
- Writing to `/boot` (Unraid flash drive) or `/dev`
- `rm -rf` in any form
- Fork bombs
- Piping to destructive commands

### Path Restrictions
| Action | Allowed | Blocked |
|--------|---------|---------|
| **Read** | Most paths | `/etc/shadow`, `/boot/config/shadow`, `/boot/config/smbpasswd` |
| **Write** | `/mnt/user`, `/mnt/cache`, `/mnt/disk`, `/tmp` | `/boot`, `/etc`, `/usr`, `/bin`, `/dev`, `/proc`, `/sys` |

### Inside Containers
Commands run via `docker_exec` are **more permissive** since containers are isolated. Only universal dangers (fork bombs, device writes) are blocked.

### Output Limits
Command output is capped at **64 KB** to prevent context window blowouts. Oversized output shows the first and last portions.

---

## Installation

### Prerequisites
- [uv](https://docs.astral.sh/uv/) installed on your local machine
- SSH enabled on your Unraid server (Settings → Management Access → SSH)
- Your Unraid root password

### Setup

1. **Clone the repo:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/unraid-ssh-mcp.git
   cd unraid-ssh-mcp
   ```

2. **Create your `.env` file:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your Unraid SSH credentials:
   ```
   SSH_HOST=192.168.0.150
   SSH_PORT=22
   SSH_USER=root
   SSH_PASSWORD=your-password-here
   ```

3. **Install dependencies:**
   ```bash
   uv sync
   ```

4. **Test it works:**
   ```bash
   uv run unraid-ssh-mcp
   ```
   (It will start the MCP server on stdio — Ctrl+C to stop.)

---

## Claude Desktop Configuration

Add this to your `claude_desktop_config.json`:

**Windows** — `%APPDATA%\Claude\claude_desktop_config.json`
**macOS** — `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "unraid-ssh": {
      "command": "C:\\Users\\YOUR_USER\\.local\\bin\\uv.exe",
      "args": [
        "run",
        "--directory",
        "C:\\Users\\YOUR_USER\\Desktop\\Nick's Projects\\unraid-ssh-mcp",
        "unraid-ssh-mcp"
      ],
      "env": {
        "SSH_HOST": "192.168.0.150",
        "SSH_PORT": "22",
        "SSH_USER": "root",
        "SSH_PASSWORD": "your-password-here"
      }
    }
  }
}
```

> **Tip:** You can put credentials in the `env` block (as above) or in a `.env` file in the project directory. The `env` block takes priority.

Restart Claude Desktop after saving. The `unraid-ssh` tools should appear in the MCP tools menu (🔌 icon).

---

## Example Usage

```
You: What environment variables does the n8n container have?
Claude: [calls docker_inspect("n8n")]

You: Check the last 50 lines of syslog
Claude: [calls tail_log("/var/log/syslog", 50)]

You: What's using the most CPU right now?
Claude: [calls system_overview()]

You: Run `ip addr` on the server
Claude: [calls run_command("ip addr")]

You: How much memory is each container using?
Claude: [calls docker_stats()]
```

---

## Customising Guardrails

The blocklists and path restrictions live in `src/unraid_ssh_mcp/guardrails.py`. You can edit them to match your needs:

- **`BLOCKED_HOST_COMMANDS`** — set of command names blocked on the host
- **`BLOCKED_PATTERNS`** — regex patterns blocked everywhere
- **`BLOCKED_HOST_PATTERNS`** — regex patterns blocked on host only
- **`BLOCKED_READ_PATHS`** — paths that can't be read
- **`BLOCKED_WRITE_PATHS`** — paths that can't be written to
- **`ALLOWED_WRITE_PATHS`** — paths that *can* be written to

---

## Architecture

```
Claude Desktop
    │
    ▼ (MCP / stdio)
unraid-ssh-mcp
    │
    ├── guardrails.py   ← validates every command before execution
    ├── ssh_client.py   ← persistent SSH connection with auto-reconnect
    └── server.py       ← MCP tool definitions
            │
            ▼ (SSH)
    Unraid Server (root@192.168.0.150)
```

---

## Companion: unraid-mcp (GraphQL)

This project is designed to work alongside [unraid-mcp](https://github.com/chrisbenincasa/unraid-mcp) which provides:
- Array health and disk status
- Container start/stop via the Unraid API
- Notification management
- VM management

**unraid-ssh-mcp** adds the missing pieces: `docker exec`, env vars, file operations, and host-level commands.

---

## License

MIT
