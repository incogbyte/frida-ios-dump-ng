"""Command-line interface for frida-ios-dump-ng.

Provides the main entry point and CLI argument handling for extracting
decrypted IPAs from jailbroken iOS devices using Frida.
"""

import argparse
import getpass
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from typing import List, Optional, Set

import frida

from .device import DeviceContext, connect_device
from .dumper import FridaDumper
from .builder import build_ipa
from .diff import print_diff
from .log import get_logger, setup_logging
from .metadata import print_metadata
from .progress import ProgressBar
from .ssh import SshConfig
from .transfer import (
    TransferConfig,
    enumerate_bundle_files,
    pull_bundle_via_frida,
    pull_file_via_frida,
)
from .utils import prompt_choice, sanitize_filename

log = get_logger(__name__)


# ============================================================================
# CLI Argument Parsing
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Extract a decrypted IPA from a jailbroken iOS device using Frida."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="App name/bundle id for a running app (when -f/--pid is not used)",
    )
    parser.add_argument("-f", dest="spawn", help="Spawn an app by name or bundle id")
    parser.add_argument("--pid", type=int, help="Attach to an existing PID")
    parser.add_argument("-o", dest="output", help="Output IPA path")
    parser.add_argument(
        "--app-data",
        action="store_true",
        help="Dump the app data container to <AppName>-data",
    )
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Show app metadata (Info.plist, entitlements) after extraction",
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("IPA1", "IPA2"),
        help="Compare two IPA files and show differences",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Do not resume a spawned process (useful for crashy apps)",
    )
    parser.add_argument("-U", dest="usb", action="store_true", help="Use USB device")
    parser.add_argument("-H", dest="host", help="SSH host for the device")
    parser.add_argument("-P", dest="port", type=int, help="SSH port (default 22)")
    parser.add_argument("-u", dest="username", help="SSH username")
    parser.add_argument("-p", dest="password", help="SSH password")
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel download workers (default 4)",
    )
    
    # Logging options
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for verbose, -vv for debug)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output except errors",
    )
    parser.add_argument(
        "--log-file",
        dest="log_file",
        help="Write logs to file",
    )
    return parser


# ============================================================================
# App Resolution
# ============================================================================

def resolve_app(apps: List, target: str):
    """Find an app by identifier or name (case-insensitive)."""
    target_lower = target.lower()
    for app in apps:
        if app.identifier == target or app.name == target:
            return app
        name = app.name or ""
        if app.identifier.lower() == target_lower or name.lower() == target_lower:
            return app
    return None


def running_apps(apps: List, running_pids: Set[int]) -> List:
    """Filter to only running apps."""
    return [app for app in apps if getattr(app, "pid", 0) in running_pids]


def choose_running_app(apps: List):
    """Display running apps and prompt user to select one."""
    if not apps:
        raise RuntimeError("No running apps found.")

    for idx, app in enumerate(apps, start=1):
        name = app.name or app.identifier
        print(f"{idx}) {name} ({app.identifier}) pid={app.pid}")
    return prompt_choice(apps, "Select an app to extract: ")


# ============================================================================
# SSH Configuration
# ============================================================================

def get_ssh_config(args: argparse.Namespace) -> Optional[SshConfig]:
    """Build SSH config from CLI arguments."""
    if not args.host:
        return None

    port = args.port or 22
    username = args.username or input("SSH username: ")
    password = args.password or getpass.getpass("SSH password: ")
    return SshConfig(host=args.host, port=port, username=username, password=password)


# ============================================================================
# Download Handlers
# ============================================================================

@dataclass
class DownloadContext:
    """Context for download operations."""
    dumper: FridaDumper
    ctx: DeviceContext
    attach_timeout: float
    transfer_config: TransferConfig


class BundleDownloader:
    """Handles bundle download with fallback strategies."""
    
    def __init__(self, context: DownloadContext):
        self._context = context
        self._log = get_logger(f"{__name__}.BundleDownloader")
    
    def download_bundle(
        self,
        bundle_path: str,
        local_bundle_dir: str,
        remote_dump_path: str,
        local_decrypted: str,
    ) -> None:
        """Download the app bundle and decrypted binary."""
        ctx = self._context.ctx
        config = self._context.transfer_config
        
        if ctx.ssh:
            self._download_via_ssh(
                bundle_path, local_bundle_dir, remote_dump_path, local_decrypted
            )
        else:
            self._download_via_frida(
                bundle_path, local_bundle_dir, remote_dump_path, local_decrypted, config
            )
    
    def download_sandbox(self, sandbox_path: str, sandbox_out_dir: str) -> None:
        """Download the app sandbox directory."""
        ctx = self._context.ctx
        config = self._context.transfer_config
        
        if ctx.ssh:
            self._download_dir_via_ssh(sandbox_path, sandbox_out_dir, "Downloading sandbox")
        else:
            self._download_dir_via_frida(
                sandbox_path, sandbox_out_dir, "Downloading sandbox", config
            )
    
    def _download_via_ssh(
        self,
        bundle_path: str,
        local_bundle_dir: str,
        remote_dump_path: str,
        local_decrypted: str,
    ) -> None:
        """Download bundle via SSH/SFTP."""
        ctx = self._context.ctx
        
        log.info("Scanning bundle over SSH...")
        bundle_files, bundle_dirs = ctx.ssh.walk(bundle_path)
        bundle_total = sum(size for _, _, size in bundle_files)
        dump_size = ctx.ssh.stat(remote_dump_path).st_size
        
        self._log.debug(f"Bundle: {len(bundle_files)} files, {bundle_total} bytes")
        self._log.debug(f"Dump size: {dump_size} bytes")
        
        progress = ProgressBar(bundle_total + dump_size, label="Downloading")

        ctx.ssh.download_dir(
            bundle_path,
            local_bundle_dir,
            files=bundle_files,
            dirs=bundle_dirs,
            progress=progress,
        )
        ctx.ssh.download_file(remote_dump_path, local_decrypted, progress=progress)
        progress.finish()
    
    def _download_via_frida(
        self,
        bundle_path: str,
        local_bundle_dir: str,
        remote_dump_path: str,
        local_decrypted: str,
        config: TransferConfig,
    ) -> None:
        """Download bundle via Frida RPC with fallback."""
        ctx = self._context.ctx
        dumper = self._context.dumper
        
        log.info("Scanning bundle via Frida...")
        try:
            bundle_dirs, bundle_files, bundle_sizes, bundle_total = enumerate_bundle_files(
                dumper, bundle_path, config
            )
            dump_stat = dumper.stat_path(remote_dump_path)
            dump_size = int(dump_stat.get("size", 0))
            
            self._log.debug(f"Bundle: {len(bundle_files)} files, {bundle_total} bytes")
            self._log.debug(f"Dump size: {dump_size} bytes")
            
            progress = ProgressBar(bundle_total + dump_size, label="Downloading")

            pull_bundle_via_frida(
                dumper,
                bundle_path,
                local_bundle_dir,
                config,
                files=bundle_files,
                dirs=bundle_dirs,
                sizes=bundle_sizes,
                progress=progress,
            )
            pull_file_via_frida(
                dumper,
                remote_dump_path,
                local_decrypted,
                size=dump_size,
                progress=progress,
            )
            progress.finish()
            
        except (frida.InvalidOperationError, frida.TransportError) as exc:
            self._handle_frida_error(
                exc, bundle_path, local_bundle_dir, remote_dump_path, local_decrypted, config
            )
    
    def _handle_frida_error(
        self,
        exc: Exception,
        bundle_path: str,
        local_bundle_dir: str,
        remote_dump_path: str,
        local_decrypted: str,
        config: TransferConfig,
    ) -> None:
        """Handle Frida session loss with fallback strategies."""
        ctx = self._context.ctx
        dumper = self._context.dumper
        
        log.warning(f"Frida session lost: {exc}")
        
        if ctx.ssh:
            log.info("Falling back to SSH download...")
            self._download_via_ssh(
                bundle_path, local_bundle_dir, remote_dump_path, local_decrypted
            )
        elif self._switch_to_transfer_process():
            log.info("Retrying download with transfer process...")
            self._download_via_frida(
                bundle_path, local_bundle_dir, remote_dump_path, local_decrypted, config
            )
        else:
            raise SystemExit(
                "Frida session lost while downloading. "
                "Retry with --no-resume or use SSH transfer (-H/-u/-p)."
            ) from exc
    
    def _download_dir_via_ssh(
        self,
        remote_path: str,
        local_dir: str,
        label: str,
    ) -> None:
        """Download a directory via SSH."""
        ctx = self._context.ctx
        
        log.info(f"Scanning {label.lower()} over SSH...")
        files, dirs = ctx.ssh.walk(remote_path)
        total = sum(size for _, _, size in files)
        
        self._log.debug(f"{label}: {len(files)} files, {total} bytes")
        
        progress = ProgressBar(total, label=label)
        ctx.ssh.download_dir(
            remote_path,
            local_dir,
            files=files,
            dirs=dirs,
            progress=progress,
        )
        progress.finish()
    
    def _download_dir_via_frida(
        self,
        remote_path: str,
        local_dir: str,
        label: str,
        config: TransferConfig,
    ) -> None:
        """Download a directory via Frida RPC."""
        ctx = self._context.ctx
        dumper = self._context.dumper
        
        log.info(f"Scanning {label.lower()} via Frida...")
        try:
            dirs, files, sizes, total = enumerate_bundle_files(dumper, remote_path, config)
            
            self._log.debug(f"{label}: {len(files)} files, {total} bytes")
            
            progress = ProgressBar(total, label=label)
            pull_bundle_via_frida(
                dumper,
                remote_path,
                local_dir,
                config,
                files=files,
                dirs=dirs,
                sizes=sizes,
                progress=progress,
            )
            progress.finish()
            
        except (frida.InvalidOperationError, frida.TransportError) as exc:
            log.warning(f"Frida session lost: {exc}")
            
            if ctx.ssh:
                log.info("Falling back to SSH download...")
                self._download_dir_via_ssh(remote_path, local_dir, label)
            elif self._switch_to_transfer_process():
                log.info(f"Retrying {label.lower()} download with transfer process...")
                dirs, files, sizes, total = enumerate_bundle_files(dumper, remote_path, config)
                progress = ProgressBar(total, label=label)
                pull_bundle_via_frida(
                    dumper,
                    remote_path,
                    local_dir,
                    config,
                    files=files,
                    dirs=dirs,
                    sizes=sizes,
                    progress=progress,
                )
                progress.finish()
            else:
                raise SystemExit(
                    f"Frida session lost while downloading. "
                    "Retry with --no-resume or use SSH transfer (-H/-u/-p)."
                ) from exc
    
    def _switch_to_transfer_process(self) -> bool:
        """Switch to a stable system process for file transfer."""
        ctx = self._context.ctx
        dumper = self._context.dumper
        
        candidates = ["SpringBoard", "backboardd", "launchd", "installd"]
        try:
            processes = ctx.device.enumerate_processes()
        except Exception:
            return False

        for name in candidates:
            proc = next((p for p in processes if p.name == name), None)
            if proc and proc.pid != dumper.pid:
                log.info(f"Switching transfer process to {name} (pid {proc.pid})")
                try:
                    dumper.detach()
                except Exception:
                    pass
                dumper.attach(proc.pid, retries=1, timeout=self._context.attach_timeout)
                return True
        return False


# ============================================================================
# Attachment Helpers
# ============================================================================

def spawn_fallback(dumper: FridaDumper, app, reason: str, resume: bool) -> bool:
    """Offer to spawn an app if attach fails."""
    if app and getattr(app, "identifier", None) and sys.stdin.isatty():
        log.warning(reason)
        answer = input(f"Spawn {app.identifier} instead? [y/N] ").strip().lower()
        if answer in {"y", "yes"}:
            log.info(f"Spawning {app.identifier}")
            dumper.spawn(app.identifier, resume=resume)
            return True
    return False


def attach_to_target(
    args: argparse.Namespace,
    ctx: DeviceContext,
    dumper: FridaDumper,
    apps: List,
    processes: List,
    running_pids: Set[int],
    attach_timeout: float,
):
    """Attach or spawn based on CLI arguments. Returns (identifier, name)."""
    resume = not args.no_resume
    
    if args.pid:
        return _attach_by_pid(
            args.pid, apps, processes, running_pids, dumper, attach_timeout, resume
        )
    elif args.spawn:
        return _spawn_app(args.spawn, apps, dumper, resume)
    else:
        return _attach_running(args.target, apps, running_pids, dumper, attach_timeout, resume)


def _attach_by_pid(
    pid: int,
    apps: List,
    processes: List,
    running_pids: Set[int],
    dumper: FridaDumper,
    attach_timeout: float,
    resume: bool,
):
    """Attach to a specific PID."""
    log.info(f"Attaching to PID {pid}")
    
    app_by_pid = next((app for app in apps if app.pid == pid), None)
    proc_by_pid = next((proc for proc in processes if proc.pid == pid), None)
    
    identifier = app_by_pid.identifier if app_by_pid else None
    name = app_by_pid.name if app_by_pid else (proc_by_pid.name if proc_by_pid else None)
    
    if pid not in running_pids:
        raise SystemExit(f"PID {pid} is not running. Use -f to spawn the app.")
    
    try:
        dumper.attach(pid, retries=1, timeout=attach_timeout)
    except (frida.TransportError, frida.NotSupportedError, frida.OperationCancelledError) as exc:
        if not (app_by_pid and spawn_fallback(dumper, app_by_pid, f"Attach failed: {exc}", resume)):
            raise
    
    return identifier, name


def _spawn_app(target: str, apps: List, dumper: FridaDumper, resume: bool):
    """Spawn an app by name or bundle ID."""
    app = resolve_app(apps, target)
    identifier = app.identifier if app else target
    name = app.name if app else None
    
    log.info(f"Spawning {identifier}")
    dumper.spawn(identifier, resume=resume)
    
    return identifier, name


def _attach_running(
    target: Optional[str],
    apps: List,
    running_pids: Set[int],
    dumper: FridaDumper,
    attach_timeout: float,
    resume: bool,
):
    """Attach to a running app."""
    if target:
        app = resolve_app(apps, target)
        if not app or app.pid not in running_pids:
            raise SystemExit(f"App '{target}' is not running. Use -f to spawn it.")
    else:
        available = running_apps(apps, running_pids)
        if not available:
            raise SystemExit("No running apps found. Use -f to spawn the app.")
        app = choose_running_app(available)
    
    name = app.name or app.identifier
    log.info(f"Attaching to {name} (pid {app.pid})")
    
    try:
        dumper.attach(app.pid, retries=1, timeout=attach_timeout)
    except (frida.TransportError, frida.OperationCancelledError) as exc:
        if not spawn_fallback(dumper, app, f"Attach timed out: {exc}", resume):
            raise
    except frida.NotSupportedError as exc:
        if not spawn_fallback(dumper, app, f"Attach not supported: {exc}", resume):
            raise
    
    return app.identifier, app.name


# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> None:
    """Main entry point for frida-ios-dump-ng."""
    args = build_parser().parse_args()
    
    # Setup logging first
    setup_logging(
        verbosity=args.verbose,
        quiet=args.quiet,
        log_file=args.log_file,
    )
    
    # Handle diff mode (standalone, doesn't need device)
    if args.diff:
        print_diff(args.diff[0], args.diff[1])
        return

    if args.spawn and args.pid:
        raise SystemExit("Choose either -f or --pid, not both.")

    ssh_config = get_ssh_config(args)
    use_usb = args.usb or not args.host

    log.debug(f"USB mode: {use_usb}, SSH config: {ssh_config is not None}")
    
    ctx = connect_device(use_usb=use_usb, ssh_config=ssh_config)
    dumper = FridaDumper(ctx.device)
    transfer_config = TransferConfig(max_workers=args.workers)

    try:
        _print_connection_info(ctx, use_usb)
        
        apps = ctx.device.enumerate_applications()
        processes = _safe_enumerate_processes(ctx.device)
        running_pids = {proc.pid for proc in processes}
        attach_timeout = 6.0
        
        log.debug(f"Found {len(apps)} apps, {len(processes)} processes")

        try:
            selected_identifier, selected_name = attach_to_target(
                args, ctx, dumper, apps, processes, running_pids, attach_timeout
            )
        except frida.TransportError:
            raise SystemExit(
                "Frida attach timed out. Try `-f` to spawn the app, "
                "or verify frida-server is running and matches the client version."
            )
        except frida.OperationCancelledError:
            raise SystemExit("Frida attach timed out. Try `-f` to spawn the app.")
        except frida.NotSupportedError:
            raise SystemExit(
                "Frida could not attach to the running process. "
                "Some apps block attach; try `-f` to spawn instead."
            )

        # Get bundle info and prepare paths
        info = dumper.get_bundle_info()
        app_name = (
            info.get("appName")
            or selected_name
            or selected_identifier
            or info.get("executableName")
        )
        output_path = args.output or (sanitize_filename(app_name) + ".ipa")

        bundle_path = info.get("bundlePath")
        executable_name = info.get("executableName")
        bundle_id = info.get("bundleId") or selected_identifier
        
        if not bundle_path or not executable_name:
            raise SystemExit("Unable to resolve bundle path or executable name.")
        
        dump_dir = bundle_id or sanitize_filename(app_name)
        remote_dump_path = f"/tmp/frida-ios-dump-ng/{dump_dir}/{executable_name}.decrypted"

        _print_extraction_info(bundle_id, bundle_path, executable_name, output_path)

        # Dump the decrypted binary
        log.info("Dumping decrypted binary via Frida...")
        dumper.dump_executable(remote_dump_path)
        log.debug(f"Dumped to: {remote_dump_path}")

        # Handle app-data option
        app_data_path = None
        app_data_out_dir = None
        if args.app_data:
            app_data_path = dumper.get_sandbox_path()
            if not app_data_path:
                raise SystemExit("Unable to resolve app data path.")
            app_data_out_dir = f"{sanitize_filename(app_name)}-data"
            if os.path.exists(app_data_out_dir):
                raise SystemExit(f"App data output directory already exists: {app_data_out_dir}")
            log.info(f"App data path: {app_data_path}")

        # Create download context and handler
        download_ctx = DownloadContext(
            dumper=dumper,
            ctx=ctx,
            attach_timeout=attach_timeout,
            transfer_config=transfer_config,
        )
        downloader = BundleDownloader(download_ctx)

        # Download bundle and build IPA
        with tempfile.TemporaryDirectory() as tmpdir:
            local_bundle_dir = os.path.join(tmpdir, os.path.basename(bundle_path))
            local_decrypted = os.path.join(tmpdir, f"{executable_name}.decrypted")

            downloader.download_bundle(
                bundle_path, local_bundle_dir, remote_dump_path, local_decrypted
            )

            # Replace binary with decrypted version
            local_bin_path = os.path.join(local_bundle_dir, executable_name)
            shutil.copy2(local_decrypted, local_bin_path)
            log.debug(f"Copied decrypted binary to {local_bin_path}")

            log.info(f"Building IPA at {output_path}...")
            build_ipa(local_bundle_dir, output_path)

        # Download app data if requested
        if args.app_data and app_data_path and app_data_out_dir:
            downloader.download_sandbox(app_data_path, app_data_out_dir)
        
        # Show metadata if requested
        if args.metadata:
            print()
            print_metadata(output_path)

        # Cleanup
        _cleanup_remote(dumper, remote_dump_path)
        log.info("Done.")

    finally:
        _cleanup_session(dumper, ctx)


def _print_connection_info(ctx: DeviceContext, use_usb: bool) -> None:
    """Print connection mode information."""
    if use_usb:
        log.info("Connection: USB")
    else:
        log.info("Connection: remote Frida (SSH tunnel)")
    
    if ctx.ssh:
        log.info("Transfer: SSH/SFTP")
    else:
        log.info("Transfer: Frida RPC")


def _print_extraction_info(
    bundle_id: Optional[str],
    bundle_path: str,
    executable_name: str,
    output_path: str,
) -> None:
    """Print extraction target information."""
    log.info(f"Bundle ID: {bundle_id or 'unknown'}")
    log.info(f"Bundle path: {bundle_path}")
    log.info(f"Executable: {executable_name}")
    log.info(f"Output: {output_path}")


def _safe_enumerate_processes(device) -> List:
    """Safely enumerate processes, returning empty list on error."""
    try:
        return device.enumerate_processes()
    except Exception as e:
        log.debug(f"Failed to enumerate processes: {e}")
        return []


def _cleanup_remote(dumper: FridaDumper, remote_path: str) -> None:
    """Clean up remote dump file."""
    try:
        dumper.remove_path(remote_path)
        log.debug(f"Removed remote file: {remote_path}")
    except Exception as e:
        log.debug(f"Failed to remove remote file: {e}")


def _cleanup_session(dumper: FridaDumper, ctx: DeviceContext) -> None:
    """Clean up Frida session and device context."""
    try:
        dumper.detach()
        log.debug("Detached from process")
    except Exception:
        pass
    try:
        ctx.close()
        log.debug("Closed device context")
    except Exception:
        pass


if __name__ == "__main__":
    main()
