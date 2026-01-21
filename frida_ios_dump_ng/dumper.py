"""Frida client module for iOS app interaction.

Provides FridaDumper class for attaching to processes, injecting the
Frida agent, and calling RPC methods to extract app data.
"""

import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import frida

from .log import get_logger

log = get_logger(__name__)


class FridaDumper:
    """Client for interacting with iOS apps via Frida.
    
    Handles process attachment, agent injection, and RPC communication
    for extracting decrypted binaries and app data.
    """
    
    def __init__(self, device: frida.core.Device):
        self._device = device
        self._session: Optional[frida.core.Session] = None
        self._script: Optional[frida.core.Script] = None
        self._pid: Optional[int] = None

    def attach(
        self,
        pid: int,
        retries: int = 3,
        delay: float = 0.5,
        timeout: Optional[float] = None,
    ) -> None:
        """Attach to a running process by PID.
        
        Args:
            pid: Process ID to attach to
            retries: Number of retry attempts
            delay: Delay between retries in seconds
            timeout: Optional timeout for the attach operation
        """
        self._attach_with_retries(pid, retries=retries, delay=delay, timeout=timeout)
        self._pid = pid

    def spawn(
        self,
        target: str,
        retries: int = 3,
        delay: float = 0.5,
        resume: bool = True,
    ) -> int:
        """Spawn and attach to an app by bundle ID.
        
        Args:
            target: Bundle identifier or app name
            retries: Number of retry attempts for attachment
            delay: Delay between retries in seconds
            resume: Whether to resume the process after attaching
            
        Returns:
            PID of the spawned process
        """
        pid = self._device.spawn([target])
        log.debug(f"Spawned process with PID {pid}")
        self._attach_with_retries(pid, retries=retries, delay=delay)
        if resume:
            self._device.resume(pid)
            log.debug(f"Resumed process {pid}")
        self._pid = pid
        return pid

    def _attach_with_retries(
        self,
        target: int,
        retries: int,
        delay: float,
        timeout: Optional[float] = None,
    ) -> None:
        """Internal method to attach with retry logic."""
        last_error: Optional[Exception] = None
        
        for attempt in range(1, retries + 1):
            try:
                if retries > 1:
                    log.debug(f"Attach attempt {attempt}/{retries}...")
                
                if timeout is None:
                    self._session = self._device.attach(target)
                else:
                    cancellable = frida.Cancellable()
                    timer = threading.Timer(timeout, cancellable.cancel)
                    timer.start()
                    try:
                        self._session = self._device.attach(target, cancellable=cancellable)
                    finally:
                        timer.cancel()
                
                self._load_agent()
                log.debug(f"Successfully attached to PID {target}")
                return
                
            except (frida.TransportError, frida.OperationCancelledError) as exc:
                last_error = exc
                log.debug(f"Attach attempt {attempt} failed: {exc}")
                time.sleep(delay)
        
        if last_error:
            raise last_error

    def _load_agent(self) -> None:
        """Load the Frida agent script."""
        agent_path = Path(__file__).with_name("agent.js")
        source = agent_path.read_text(encoding="utf-8")
        
        if not self._session:
            raise RuntimeError("No active session")
        
        script = self._session.create_script(source)
        script.on("message", self._on_message)
        script.load()
        self._script = script
        log.debug("Agent script loaded")

    def _on_message(self, message: Dict[str, Any], data: Any) -> None:
        """Handle messages from the Frida agent."""
        msg_type = message.get("type")
        
        if msg_type == "error":
            description = message.get("stack") or message.get("description")
            log.error(f"[agent] {description}")
        elif msg_type == "send":
            payload = message.get("payload")
            log.debug(f"[agent] {payload}")

    def get_bundle_info(self, retries: int = 40, delay: float = 0.25) -> Dict[str, Any]:
        """Get app bundle information.
        
        Retries are needed because the ObjC runtime may not be ready immediately.
        
        Returns:
            Dictionary with appName, bundlePath, executablePath, executableName, bundleId
        """
        last_error: Optional[Exception] = None
        
        for attempt in range(retries):
            try:
                info = self._script.exports.getbundleinfo()
                log.debug(f"Got bundle info on attempt {attempt + 1}")
                return info
            except Exception as exc:
                last_error = exc
                time.sleep(delay)
        
        raise RuntimeError("Failed to fetch bundle info") from last_error

    def dump_executable(self, out_path: str) -> Dict[str, Any]:
        """Dump the decrypted executable to the specified path.
        
        Args:
            out_path: Remote path to write the decrypted binary
            
        Returns:
            Dictionary with outPath, bundlePath, executableName
        """
        log.debug(f"Dumping executable to {out_path}")
        result = self._script.exports.dumpexecutable(out_path)
        log.debug("Executable dump complete")
        return result

    def get_sandbox_path(self) -> Optional[str]:
        """Get the app's sandbox (home) directory path."""
        path = self._script.exports.getsandboxpath()
        log.debug(f"Sandbox path: {path}")
        return path

    def list_files(self, root_path: str) -> Dict[str, List[str]]:
        """List files and directories under a path.
        
        Returns:
            Dictionary with 'files' and 'dirs' lists of relative paths
        """
        result = self._script.exports.listfiles(root_path)
        log.debug(f"Listed {len(result.get('files', []))} files, {len(result.get('dirs', []))} dirs")
        return result

    def stat_path(self, path: str) -> Dict[str, Any]:
        """Get file status for a single path.
        
        Returns:
            Dictionary with exists, isDir, size fields
        """
        return self._script.exports.statpath(path)

    def stat_paths(self, paths: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get file status for multiple paths in one call.
        
        Args:
            paths: List of paths to stat
            
        Returns:
            Dictionary mapping each path to its stat result
        """
        log.debug(f"Batch stat for {len(paths)} paths")
        return self._script.exports.statpaths(paths)

    def read_file(self, path: str, offset: int, size: int) -> bytes:
        """Read a chunk of data from a remote file.
        
        Args:
            path: Remote file path
            offset: Byte offset to start reading
            size: Number of bytes to read
            
        Returns:
            File data as bytes
        """
        return self._script.exports.readfile(path, offset, size)

    def remove_path(self, path: str) -> bool:
        """Remove a file on the remote device.
        
        Returns:
            True if successful
        """
        log.debug(f"Removing remote path: {path}")
        return self._script.exports.removepath(path)

    def detach(self) -> None:
        """Detach from the current session."""
        if self._session:
            self._session.detach()
            self._session = None
            self._script = None
            self._pid = None
            log.debug("Detached from session")

    @property
    def pid(self) -> Optional[int]:
        """Get the PID of the attached process."""
        return self._pid
