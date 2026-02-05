"""
SSH client wrapper for Unraid SSH MCP Server.

Manages a persistent SSH connection to the Unraid server with automatic
reconnection on failure.
"""

import os
import logging
from typing import Tuple, Optional

import paramiko

logger = logging.getLogger("unraid-ssh-mcp")


class SSHConnectionError(Exception):
    """Raised when SSH connection fails."""
    pass


class SSHClient:
    """Persistent SSH client with auto-reconnect."""

    def __init__(self):
        self.host = os.getenv("SSH_HOST", "192.168.0.150")
        self.port = int(os.getenv("SSH_PORT", "22"))
        self.username = os.getenv("SSH_USER", "root")
        self.password = os.getenv("SSH_PASSWORD")
        self.key_path = os.getenv("SSH_KEY_PATH")
        self.timeout = int(os.getenv("SSH_TIMEOUT", "30"))
        self._client: Optional[paramiko.SSHClient] = None

    def _is_connected(self) -> bool:
        """Check if the SSH connection is still alive."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            return False
        try:
            transport.send_ignore()
            return True
        except Exception:
            return False

    def connect(self) -> None:
        """Establish or verify SSH connection."""
        if self._is_connected():
            return

        # Close stale connection
        self.disconnect()

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
            connect_kwargs["look_for_keys"] = True
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            raise SSHConnectionError(
                "No SSH credentials configured. "
                "Set SSH_PASSWORD or SSH_KEY_PATH in your .env file."
            )

        try:
            self._client.connect(**connect_kwargs)
            logger.info(f"SSH connected to {self.username}@{self.host}:{self.port}")
        except paramiko.AuthenticationException:
            self._client = None
            raise SSHConnectionError(
                f"SSH authentication failed for {self.username}@{self.host}. "
                "Check your SSH_PASSWORD or SSH_KEY_PATH."
            )
        except Exception as e:
            self._client = None
            raise SSHConnectionError(
                f"SSH connection failed to {self.host}:{self.port} — {e}"
            )

    def execute(self, command: str, timeout: Optional[int] = None) -> Tuple[str, str, int]:
        """
        Execute a command over SSH.

        Returns:
            (stdout, stderr, exit_code)
        """
        self.connect()

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout or self.timeout,
            )
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return out, err, exit_code

        except Exception as e:
            # Connection might have dropped mid-command — try once more
            logger.warning(f"Command failed, reconnecting: {e}")
            self.disconnect()
            self.connect()

            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout or self.timeout,
            )
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return out, err, exit_code

    def disconnect(self) -> None:
        """Close the SSH connection."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
