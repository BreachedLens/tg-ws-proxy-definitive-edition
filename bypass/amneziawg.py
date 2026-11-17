"""Embedded AmneziaWG tunnel transport (Quad9 DNS by default).

Parses AmneziaWG ``.conf`` profiles — including the obfuscation fields
``Jc``, ``Jmin``, ``Jmax``, ``S1``, ``S2``, ``H1``-``H4`` — and manages a
userspace tunnel. Windows uses the official ``amneziawg.exe`` tunnel-service
commands; Linux and macOS retain ``amneziawg-go``/``wireguard-go`` and
``awg-quick``/``wg-quick`` support.

Privileges: creating a TUN device requires administrator rights on Windows
and root/CAP_NET_ADMIN on Linux. Without them the transport raises
:class:`BypassUnavailable` with a clear message instead of half-starting.

DNS: by default Quad9 (9.9.9.9 / 149.112.112.112) is written into the
rendered profile. ``amneziawg-go`` only brings the interface up, so when
``manage_dns`` is enabled and a network interface is named, system DNS is
applied with platform-specific helpers (see :func:`apply_system_dns`).
DoH/DoT endpoints (``dns.quad9.net``) are exposed as constants so the UI
can offer them as a resolver hint in Phase 2.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .base import (
    BypassConnectError,
    BypassTransport,
    BypassUnavailable,
    ConnectRequest,
    ConnectResult,
)

log = logging.getLogger("bypass.amneziawg")

QUAD9_IPV4 = ("9.9.9.9", "149.112.112.112")
QUAD9_IPV6 = ("2620:fe::fe", "2620:fe::9")
QUAD9_DOH = "https://dns.quad9.net/dns-query"
QUAD9_DOT = "dns.quad9.net"

OBFUSCATION_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
REQUIRED_OBFUSCATION_KEYS = OBFUSCATION_KEYS

_KEY_B64_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_KEY_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_GO_CANDIDATES = ("amneziawg-go", "awg-go", "wireguard-go")
_QUICK_CANDIDATES = ("awg-quick", "wg-quick")
_WINDOWS_SERVICE_BINARY = "amneziawg.exe"
_WIN_DIRS = (
    r"C:\Program Files\AmneziaWG",
    r"C:\Program Files (x86)\AmneziaWG",
    r"C:\Program Files\WireGuard",
)
_UNIX_DIRS = (
    "/usr/bin", "/usr/local/bin", "/usr/local/sbin",
    "/opt/homebrew/bin", "/snap/bin",
)

_ERROR_MARKERS = ("failed", "unable", "cannot", "error", "fatal", "wintun", "rtnetlink")


def _which(name: str) -> Optional[str]:
    """Indirection over shutil.which so tests can patch it."""
    return shutil.which(name)


def _is_valid_key(value: str) -> bool:
    return bool(_KEY_B64_RE.match(value) or _KEY_HEX_RE.match(value))


def _to_int(raw: Optional[str]) -> Optional[int]:
    try:
        return int(str(raw).strip(), 0)
    except (TypeError, ValueError):
        return None


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _split_sections(text: str) -> Dict[str, Dict[str, str]]:
    """Minimal INI parser for wg/awg profiles (keys are case-sensitive)."""
    sections: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        sections[current][key.strip()] = value.strip()
    return sections


def _format_ini(sections: Dict[str, Dict[str, str]]) -> str:
    out: List[str] = []
    for name, values in sections.items():
        out.append("[{}]".format(name))
        for key, value in values.items():
            out.append("{} = {}".format(key, value))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _bundled_windows_awg() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "bin", "amneziawg", _WINDOWS_SERVICE_BINARY)


def find_tunnel_binary() -> Optional[Tuple[str, str]]:
    """Locate a tunnel binary; returns (path, style) or None.

    On Windows, prefer the official AmneziaWG tunnel-service binary bundled
    with the project, then its standard installation path, then PATH. The
    ``windows-service`` style uses /installtunnelservice and
    /uninstalltunnelservice. Other platforms retain the go/quick discovery.
    """
    if sys.platform == "win32":
        bundled = _bundled_windows_awg()
        if os.path.isfile(bundled):
            return bundled, "windows-service"
        installed = os.path.join(_WIN_DIRS[0], _WINDOWS_SERVICE_BINARY)
        if os.path.isfile(installed):
            return installed, "windows-service"
        found = _which("amneziawg.exe") or _which("amneziawg")
        if found:
            return found, "windows-service"

    groups = ((_GO_CANDIDATES, "go"), (_QUICK_CANDIDATES, "quick"))
    dirs = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    dirs.extend(_WIN_DIRS if sys.platform == "win32" else _UNIX_DIRS)
    for group, style in groups:
        for name in group:
            exe = name + (".exe" if sys.platform == "win32" else "")
            found = _which(name)
            if found:
                return found, style
            for directory in dirs:
                path = os.path.join(directory, exe)
                if os.path.isfile(path):
                    return path, style
    return None


@dataclass
class InterfaceConfig:
    private_key: str
    addresses: List[str]
    dns: List[str]
    mtu: Optional[int]
    obfuscation: Dict[str, int] = field(default_factory=dict)


@dataclass
class PeerConfig:
    public_key: str
    preshared_key: Optional[str]
    endpoint: str
    allowed_ips: List[str]
    keepalive: Optional[int]


@dataclass
class AmneziaConfig:
    """Parsed AmneziaWG/WireGuard profile."""

    interface: InterfaceConfig
    peer: Optional[PeerConfig]
    raw: Dict[str, Dict[str, str]]

    @classmethod
    def parse(cls, text: str) -> "AmneziaConfig":
        sections = _split_sections(text)
        iface_raw = sections.get("Interface") or sections.get("interface") or {}
        peer_raw = sections.get("Peer") or sections.get("peer") or {}
        iface = InterfaceConfig(
            private_key=iface_raw.get("PrivateKey", ""),
            addresses=_split_csv(iface_raw.get("Address", "")),
            dns=_split_csv(iface_raw.get("DNS", "")),
            mtu=_to_int(iface_raw.get("MTU")),
            obfuscation={
                key: int(iface_raw[key])
                for key in OBFUSCATION_KEYS
                if key in iface_raw and _to_int(iface_raw[key]) is not None
            },
        )
        peer = None
        if peer_raw:
            peer = PeerConfig(
                public_key=peer_raw.get("PublicKey", ""),
                preshared_key=peer_raw.get("PresharedKey") or None,
                endpoint=peer_raw.get("Endpoint", ""),
                allowed_ips=_split_csv(peer_raw.get("AllowedIPs", "")),
                keepalive=_to_int(peer_raw.get("PersistentKeepalive")),
            )
        return cls(interface=iface, peer=peer, raw=sections)

    @classmethod
    def from_file(cls, path: str) -> "AmneziaConfig":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return cls.parse(fh.read())

    def validate(self) -> List[str]:
        errors: List[str] = []
        iface = self.interface
        raw_iface = self.raw.get("Interface") or self.raw.get("interface") or {}
        if "MTU" in raw_iface and iface.mtu is None:
            errors.append("Interface/MTU: expected an integer")
        for key in OBFUSCATION_KEYS:
            if key in raw_iface and key not in iface.obfuscation:
                errors.append("Interface/{}: expected an integer".format(key))
        if not _is_valid_key(iface.private_key):
            errors.append(
                "Interface/PrivateKey: missing or malformed "
                "(expected 32-byte base64 or 64-char hex)"
            )
        if not iface.addresses:
            errors.append("Interface/Address: no tunnel addresses defined")
        for addr in iface.addresses:
            try:
                ipaddress.ip_interface(addr)
            except ValueError:
                errors.append("Interface/Address: '{}' is not a valid IP/CIDR".format(addr))
        if iface.mtu is not None and not 576 <= iface.mtu <= 65535:
            errors.append("Interface/MTU: {} is outside 576..65535".format(iface.mtu))
        obf = iface.obfuscation
        if obf:
            missing = [k for k in REQUIRED_OBFUSCATION_KEYS if k not in obf]
            if missing:
                errors.append(
                    "AmneziaWG obfuscation incomplete, missing: " + ", ".join(missing)
                )
            jc = obf.get("Jc")
            if jc is not None and not 0 <= jc <= 128:
                errors.append("Jc={} out of range 0..128".format(jc))
            jmin, jmax = obf.get("Jmin"), obf.get("Jmax")
            for key, value in (("Jmin", jmin), ("Jmax", jmax)):
                if value is not None and not 0 <= value <= 1280:
                    errors.append("{}={} out of range 0..1280".format(key, value))
            if jmin is not None and jmax is not None and jmin > jmax:
                errors.append("Jmin ({}) must be <= Jmax ({})".format(jmin, jmax))
            s1, s2 = obf.get("S1"), obf.get("S2")
            for key, value in (("S1", s1), ("S2", s2)):
                if value is not None and not 0 <= value <= 65535:
                    errors.append("{}={} out of range 0..65535".format(key, value))
            hs = [obf.get("H{}".format(i)) for i in range(1, 5)]
            for i, h in enumerate(hs, start=1):
                if h is not None and not 0 < h <= 0xFFFFFFFF:
                    errors.append("H{}={} is not a valid uint32 > 0".format(i, h))
            present = [h for h in hs if h is not None]
            if len(set(present)) != len(present):
                errors.append("H1-H4 must be distinct values")
        if self.peer is None:
            errors.append("no [Peer] section")
        else:
            peer = self.peer
            if not _is_valid_key(peer.public_key):
                errors.append("Peer/PublicKey: missing or malformed")
            if peer.preshared_key and not _is_valid_key(peer.preshared_key):
                errors.append("Peer/PresharedKey: malformed")
            if not peer.endpoint or ":" not in peer.endpoint:
                errors.append("Peer/Endpoint: expected 'host:port'")
            if not peer.allowed_ips:
                errors.append("Peer/AllowedIPs: empty")
            for allowed_ip in peer.allowed_ips:
                try:
                    ipaddress.ip_network(allowed_ip, strict=False)
                except ValueError:
                    errors.append(
                        "Peer/AllowedIPs: '{}' is not a valid IP/CIDR".format(allowed_ip)
                    )
            if peer.keepalive is not None and peer.keepalive < 0:
                errors.append("Peer/PersistentKeepalive: negative")
        return errors

    def render(self, dns: Optional[Sequence[str]] = None) -> str:
        """Rebuild the profile; optionally override the DNS line."""
        sections = {name: dict(values) for name, values in self.raw.items()}
        if dns is not None:
            iface = sections.get("Interface") or sections.get("interface")
            if iface is not None:
                if dns:
                    iface["DNS"] = ", ".join(dns)
                else:
                    iface.pop("DNS", None)
        return _format_ini(sections)


def _sanitize_name(value: str) -> str:
    return str(value).strip().replace('"', "").replace("`", "").replace("'", "")


def _run_quiet(cmd: List[str]) -> bool:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("command %r failed: %r", cmd, exc)
        return False


def apply_system_dns(dns: Sequence[str], interface: str) -> bool:
    """Best-effort system DNS override for the tunnel interface."""
    interface = _sanitize_name(interface)
    if not interface or not dns:
        return False
    servers = ",".join(dns)
    if sys.platform == "win32":
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Set-DnsClientServerAddress -InterfaceAlias '{}' "
            "-ServerAddresses {}".format(interface, servers),
        ]
    elif sys.platform.startswith("linux"):
        cmd = ["resolvectl", "dns", interface] + list(dns)
    elif sys.platform == "darwin":
        cmd = ["networksetup", "-setdnsservers", interface] + list(dns)
    else:
        log.debug("apply_system_dns: unsupported platform %s", sys.platform)
        return False
    ok = _run_quiet(cmd)
    if ok:
        log.info("System DNS on %s set to %s", interface, servers)
    else:
        log.warning("Could not set system DNS on %s (need admin/root?)", interface)
    return ok


def revert_system_dns(interface: str) -> bool:
    """Restore default (DHCP) DNS for the interface."""
    interface = _sanitize_name(interface)
    if not interface:
        return False
    if sys.platform == "win32":
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Set-DnsClientServerAddress -InterfaceAlias '{}' "
            "-ResetServerAddresses".format(interface),
        ]
    elif sys.platform.startswith("linux"):
        cmd = ["resolvectl", "revert", interface]
    elif sys.platform == "darwin":
        cmd = ["networksetup", "-setdnsservers", interface, "Empty"]
    else:
        return False
    ok = _run_quiet(cmd)
    if ok:
        log.info("System DNS on %s reverted", interface)
    return ok


class AmneziaWGTransport(BypassTransport):
    """Userspace AmneziaWG tunnel transport.

    Brings the tunnel up as a managed child process (``start``), keeps it
    alive, and hands out plain TCP streams (``connect``) — routing happens
    at the OS level through the tunnel interface, so DNS names now resolve
    via the tunnel's Quad9 resolvers.
    """

    name = "amneziawg"
    priority = 20
    READY_TIMEOUT = 12.0
    STOP_TIMEOUT = 5.0
    DEFAULT_INTERFACE = "awg-tgproxy"

    def __init__(
        self,
        config_path: str,
        *,
        binary_path: Optional[str] = None,
        dns: Sequence[str] = QUAD9_IPV4,
        interface_name: Optional[str] = None,
        manage_dns: bool = True,
        network_interface: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.config_path = config_path
        self.binary_path = binary_path
        self.dns = tuple(dns) if dns else None
        self.interface_name = interface_name
        self.manage_dns = manage_dns
        self.network_interface = network_interface or interface_name or self.DEFAULT_INTERFACE
        self._process = None
        self._service_installed = False
        self._conf_dir: Optional[str] = None
        self._conf_file: Optional[str] = None
        self._started_at: Optional[float] = None
        self._last_output: List[str] = []
        self._dns_applied = False

    # discovery ------------------------------------------------------

    def find_binary(self) -> Optional[Tuple[str, str]]:
        if self.binary_path:
            if not os.path.isfile(self.binary_path):
                return None
            basename = os.path.basename(self.binary_path).lower()
            if sys.platform == "win32" and basename == _WINDOWS_SERVICE_BINARY:
                style = "windows-service"
            elif basename.startswith(("awg-quick", "wg-quick")):
                style = "quick"
            else:
                style = "go"
            return self.binary_path, style
        return find_tunnel_binary()

    def is_configured(self) -> bool:
        return os.path.isfile(self.config_path) and self.find_binary() is not None

    def load_config(self) -> AmneziaConfig:
        profile = AmneziaConfig.from_file(self.config_path)
        errors = profile.validate()
        if errors:
            raise BypassUnavailable(
                "AmneziaWG profile {} is invalid: {}".format(self.config_path, "; ".join(errors))
            )
        return profile

    # lifecycle ------------------------------------------------------

    @property
    def is_running(self) -> bool:
        if self._service_installed:
            return self._windows_service_running()
        return self._process is not None and self._process.poll() is None

    async def is_available(self) -> bool:
        return self.is_running

    async def start(self) -> None:
        if self.is_running:
            return
        profile = self.load_config()
        found = self.find_binary()
        if found is None:
            raise BypassUnavailable(
                "AmneziaWG/wireguard-go binary not found; "
                "install amneziawg-go or set binary_path"
            )
        binary, style = found
        rendered = profile.render(dns=self.dns)
        self._conf_dir = tempfile.mkdtemp(prefix="bypass-awg-")
        self._conf_file = os.path.join(self._conf_dir, self._iface_name() + ".conf")
        with open(self._conf_file, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        log.info(
            "Starting tunnel via %s (style=%s, profile=%s, DNS=%s)",
            binary, style, self.config_path, self.dns,
        )
        cmd = self._build_command(binary, style, self._conf_file)
        if style == "windows-service":
            self._started_at = time.monotonic()
            if not _run_quiet(cmd):
                self._cleanup_temp_config()
                raise BypassUnavailable(
                    "AmneziaWG tunnel service install failed; run as Administrator"
                )
            self._service_installed = True
            try:
                await self._wait_windows_service()
            except Exception:
                await self._uninstall_windows_service()
                self._cleanup_temp_config()
                raise
            if self.manage_dns and self.dns and self.network_interface:
                self._dns_applied = apply_system_dns(self.dns, self.network_interface)
            log.info("Tunnel service %s is up", self._service_name())
            return

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            self._cleanup_temp_config()
            raise BypassUnavailable(
                "cannot launch tunnel binary: {!r}".format(exc)
            ) from exc
        self._started_at = time.monotonic()
        try:
            await self._wait_ready(self._process)
        except Exception:
            await self._terminate(self._process)
            self._process = None
            self._cleanup_temp_config()
            raise
        if style == "go" and self.manage_dns and self.dns and self.network_interface:
            self._dns_applied = apply_system_dns(self.dns, self.network_interface)
        log.info("Tunnel %s is up (pid=%s)", self._iface_name(), self._process.pid)

    def _iface_name(self) -> str:
        return self.interface_name or self.DEFAULT_INTERFACE

    def _service_name(self) -> str:
        conf_file = self._conf_file
        if not conf_file:
            conf_file = os.path.join(tempfile.gettempdir(), self._iface_name() + ".conf")
        return os.path.splitext(os.path.basename(conf_file))[0]

    def _build_command(self, binary: str, style: str, conf_file: str) -> List[str]:
        if style == "windows-service":
            return [binary, "/installtunnelservice", conf_file]
        if style == "quick":
            return [binary, "up", conf_file]
        return [binary, "-f", self._iface_name(), conf_file]

    def _windows_service_running(self) -> bool:
        if sys.platform != "win32" or not self._service_name():
            return False
        try:
            result = subprocess.run(
                ["sc.exe", "query", "AmneziaWGTunnel$" + self._service_name()],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0 and "RUNNING" in (result.stdout or "").upper()

    async def _wait_windows_service(self) -> None:
        deadline = time.monotonic() + self.READY_TIMEOUT
        while time.monotonic() < deadline:
            if self._windows_service_running():
                return
            await asyncio.sleep(0.25)
        raise BypassUnavailable(
            "AmneziaWG service {} did not reach RUNNING state".format(
                self._service_name()
            )
        )

    async def _uninstall_windows_service(self) -> None:
        if not self._service_installed:
            return
        self._service_installed = False
        binary = self.find_binary()
        if binary is None:
            log.error("Cannot find AmneziaWG binary to uninstall tunnel service")
            return
        ok = _run_quiet([
            binary[0], "/uninstalltunnelservice", self._service_name()
        ])
        if not ok:
            log.warning("AmneziaWG tunnel service %s uninstall command failed",
                        self._service_name())

    def _cleanup_temp_config(self) -> None:
        if self._conf_dir:
            shutil.rmtree(self._conf_dir, ignore_errors=True)
            self._conf_dir = None
        self._conf_file = None

    async def _wait_ready(self, proc) -> None:
        """A live process after READY_TIMEOUT counts as up; early exit = failure."""
        output: List[str] = []
        deadline = time.monotonic() + self.READY_TIMEOUT
        while True:
            if proc.poll() is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if proc.stdout is None:
                await asyncio.sleep(0.1)
                continue
            try:
                line = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=min(0.5, remaining)
                )
            except asyncio.TimeoutError:
                continue
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            output.append(text)
        self._last_output = output
        for marker in _ERROR_MARKERS:
            for text in output:
                if marker in text.lower():
                    raise BypassUnavailable("tunnel reported an error: {}".format(text))
        if proc.poll() is not None:
            tail = "\n".join(output[-5:]) or "(no output)"
            raise BypassUnavailable(
                "tunnel process exited immediately (code {}): {}".format(
                    proc.returncode, tail
                )
            )

    async def _terminate(self, proc) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=self.STOP_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass

    async def stop(self) -> None:
        proc, self._process = self._process, None
        if self._service_installed:
            await self._uninstall_windows_service()
        if self._dns_applied and self.network_interface:
            revert_system_dns(self.network_interface)
            self._dns_applied = False
        if proc is not None:
            await self._terminate(proc)
        self._cleanup_temp_config()
        self._started_at = None
        self._last_output = []
        log.info("AmneziaWG tunnel stopped")

    # connection -----------------------------------------------------

    async def connect(self, request: ConnectRequest) -> ConnectResult:
        if not self.is_running:
            await self.start()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(request.host, request.port),
                timeout=request.timeout,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            raise BypassConnectError(
                "connect via {} tunnel failed: {!r}".format(self.name, exc)
            ) from exc
        return ConnectResult(reader=reader, writer=writer, transport=self.name)

    def status(self) -> Dict[str, object]:
        return {
            "running": self.is_running,
            "interface": self._iface_name(),
            "pid": self._process.pid if self._process else None,
            "uptime_s": (time.monotonic() - self._started_at) if self._started_at else 0.0,
            "dns": list(self.dns or ()),
            "config_path": self.config_path,
            "last_output": self._last_output[-3:],
        }
