"""Device connection module.

Handles USB and SSH-tunneled connections to iOS devices.
"""

from dataclasses import dataclass
from typing import Optional

import frida

from .ssh import SshClient, SshConfig, SshTunnel


@dataclass
class DeviceContext:
    """Context containing device connection and optional SSH resources."""
    device: frida.core.Device
    ssh: Optional[SshClient]
    tunnel: Optional[SshTunnel]

    def close(self) -> None:
        """Clean up SSH tunnel and client connections."""
        if self.tunnel:
            self.tunnel.stop()
        if self.ssh:
            self.ssh.close()


def connect_device(
    use_usb: bool,
    ssh_config: Optional[SshConfig],
    frida_port: int = 27042,
) -> DeviceContext:
    """Connect to an iOS device via USB or SSH tunnel.
    
    Args:
        use_usb: If True, connect via USB directly
        ssh_config: SSH configuration for tunneled connections
        frida_port: Port that frida-server is listening on (default 27042)
        
    Returns:
        DeviceContext with device connection and optional SSH resources
    """
    ssh_client: Optional[SshClient] = None
    tunnel: Optional[SshTunnel] = None

    if ssh_config:
        ssh_client = SshClient(ssh_config)
        ssh_client.connect()

    if use_usb:
        device = frida.get_usb_device(timeout=5)
    elif ssh_client:
        tunnel = SshTunnel(ssh_client, "127.0.0.1", frida_port)
        tunnel.start()
        manager = frida.get_device_manager()
        device = manager.add_remote_device(f"127.0.0.1:{tunnel.local_port}")
    else:
        device = frida.get_local_device()

    return DeviceContext(device=device, ssh=ssh_client, tunnel=tunnel)
