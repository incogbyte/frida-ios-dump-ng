"""SSH client module for device communication.

Provides SSH client with SFTP session reuse, SSH tunneling for Frida,
and optimized file transfer operations.
"""

import os
import posixpath
import socket
import stat
import threading
import select
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import paramiko

from .log import get_logger

log = get_logger(__name__)


@dataclass
class SshConfig:
    """SSH connection configuration."""
    host: str
    port: int
    username: str
    password: str


class SshClient:
    """SSH client with reusable SFTP session and file transfer methods."""
    
    def __init__(self, config: SshConfig, timeout: int = 10):
        self._config = config
        self._timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None
        self._lock = threading.Lock()

    def connect(self) -> None:
        """Establish SSH connection with keepalive enabled."""
        log.debug(f"Connecting to {self._config.host}:{self._config.port}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self._config.host,
            port=self._config.port,
            username=self._config.username,
            password=self._config.password,
            timeout=self._timeout,
        )
        
        # Enable keepalive to prevent connection drops
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(30)
        
        self._client = client
        log.debug("SSH connection established")

    @property
    def transport(self) -> paramiko.Transport:
        """Get the underlying SSH transport."""
        if not self._client:
            raise RuntimeError("SSH client not connected.")
        transport = self._client.get_transport()
        if not transport:
            raise RuntimeError("SSH transport not available.")
        return transport

    @property
    def sftp(self) -> paramiko.SFTPClient:
        """Get reusable SFTP session (created on first access)."""
        with self._lock:
            if self._sftp is None:
                if not self._client:
                    raise RuntimeError("SSH client not connected.")
                self._sftp = self._client.open_sftp()
                # Increase buffer size for better throughput
                self._sftp.get_channel().settimeout(60.0)
                log.debug("SFTP session opened")
            return self._sftp

    def open_sftp(self) -> paramiko.SFTPClient:
        """Legacy method - returns the reusable SFTP session."""
        return self.sftp

    def stat(self, remote_path: str) -> paramiko.SFTPAttributes:
        """Get file attributes for a remote path."""
        return self.sftp.stat(remote_path)

    def walk(self, remote_dir: str) -> Tuple[List[Tuple[str, str, int]], List[str]]:
        """Recursively walk a remote directory.
        
        Returns:
            Tuple of (files, dirs) where:
            - files: List of (remote_path, rel_path, size) tuples
            - dirs: List of relative directory paths
        """
        files: List[Tuple[str, str, int]] = []
        dirs: List[str] = []
        self._walk_sftp(self.sftp, remote_dir, "", files, dirs)
        log.debug(f"Walk complete: {len(files)} files, {len(dirs)} dirs")
        return files, dirs

    def _walk_sftp(
        self,
        sftp: paramiko.SFTPClient,
        remote_dir: str,
        rel_base: str,
        files: List[Tuple[str, str, int]],
        dirs: List[str],
    ) -> None:
        """Recursively enumerate directory contents."""
        try:
            entries = sftp.listdir_attr(remote_dir)
        except IOError as e:
            log.debug(f"Failed to list {remote_dir}: {e}")
            return
            
        for entry in entries:
            remote_path = posixpath.join(remote_dir, entry.filename)
            rel_path = posixpath.join(rel_base, entry.filename) if rel_base else entry.filename
            
            if stat.S_ISDIR(entry.st_mode):
                dirs.append(rel_path)
                self._walk_sftp(sftp, remote_path, rel_path, files, dirs)
            else:
                files.append((remote_path, rel_path, entry.st_size))

    def download_file(
        self,
        remote_path: str,
        local_path: str,
        progress: Optional[object] = None,
    ) -> None:
        """Download a single file via SFTP."""
        local_dir = os.path.dirname(local_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)
        self._download_file_sftp(self.sftp, remote_path, local_path, progress=progress)

    def download_dir(
        self,
        remote_dir: str,
        local_dir: str,
        *,
        files: Optional[List[Tuple[str, str, int]]] = None,
        dirs: Optional[List[str]] = None,
        progress: Optional[object] = None,
    ) -> None:
        """Download an entire directory via SFTP."""
        if files is None or dirs is None:
            files, dirs = self.walk(remote_dir)

        os.makedirs(local_dir, exist_ok=True)
        for rel in sorted(dirs, key=len):
            os.makedirs(os.path.join(local_dir, rel), exist_ok=True)

        log.debug(f"Downloading {len(files)} files via SFTP")
        sftp = self.sftp
        for remote_path, rel_path, _size in files:
            local_path = os.path.join(local_dir, rel_path)
            self._download_file_sftp(sftp, remote_path, local_path, progress=progress)

    def _download_file_sftp(
        self,
        sftp: paramiko.SFTPClient,
        remote_path: str,
        local_path: str,
        progress: Optional[object] = None,
    ) -> None:
        """Internal method to download a file with progress callback."""
        last = 0

        def callback(transferred: int, total: int) -> None:
            nonlocal last
            if progress is not None:
                progress.update(transferred - last)
            last = transferred

        sftp.get(remote_path, local_path, callback=callback if progress else None)

    def close(self) -> None:
        """Close SSH and SFTP connections."""
        with self._lock:
            if self._sftp:
                try:
                    self._sftp.close()
                    log.debug("SFTP session closed")
                except Exception:
                    pass
                self._sftp = None
            if self._client:
                try:
                    self._client.close()
                    log.debug("SSH connection closed")
                except Exception:
                    pass
                self._client = None


class SshTunnel:
    """SSH tunnel for forwarding local ports to remote services."""
    
    BUFFER_SIZE = 8192  # Increased from 1024 for better throughput
    
    def __init__(self, ssh_client: SshClient, remote_host: str, remote_port: int):
        self._ssh_client = ssh_client
        self._remote_host = remote_host
        self._remote_port = remote_port
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._local_port: Optional[int] = None

    @property
    def local_port(self) -> Optional[int]:
        """Get the local port the tunnel is listening on."""
        return self._local_port

    def start(self, local_host: str = "127.0.0.1", local_port: int = 0) -> None:
        """Start the SSH tunnel on the specified local address."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((local_host, local_port))
        server.listen(100)
        server.settimeout(1.0)  # Allow periodic stop checks
        
        self._server = server
        self._local_port = server.getsockname()[1]
        self._stop_event.clear()

        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        self._thread = thread
        log.debug(f"SSH tunnel started on {local_host}:{self._local_port}")

    def _accept_loop(self) -> None:
        """Accept incoming connections and spawn handlers."""
        while not self._stop_event.is_set():
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            
            thread = threading.Thread(
                target=self._handle_client, args=(client, addr), daemon=True
            )
            thread.start()

    def _handle_client(self, client: socket.socket, addr: Tuple) -> None:
        """Forward data between local client and remote service."""
        transport = self._ssh_client.transport
        try:
            chan = transport.open_channel(
                "direct-tcpip",
                (self._remote_host, self._remote_port),
                addr,
            )
        except Exception as e:
            log.debug(f"Failed to open tunnel channel: {e}")
            client.close()
            return

        try:
            while not self._stop_event.is_set():
                rlist, _, _ = select.select([client, chan], [], [], 1.0)
                
                if client in rlist:
                    data = client.recv(self.BUFFER_SIZE)
                    if not data:
                        break
                    chan.sendall(data)
                
                if chan in rlist:
                    data = chan.recv(self.BUFFER_SIZE)
                    if not data:
                        break
                    client.sendall(data)
        finally:
            chan.close()
            client.close()

    def stop(self) -> None:
        """Stop the SSH tunnel."""
        self._stop_event.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        self._thread = None
        self._local_port = None
        log.debug("SSH tunnel stopped")
