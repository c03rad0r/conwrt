#!/usr/bin/env python3
"""Auto-discover routers on the local subnet.

A fast, nmap-driven subnet scan that finds likely routers and switches by
probing for management ports (SSH 22, HTTP 80/8080/8081, HTTPS 443) and
classifying each live host by its open ports + MAC OUI vendor. Output is a
clean, dropdown-ready list (table by default, JSON with ``--json``).

This is complementary to ``auto_detect.py``:

* ``auto_detect.py`` does *deep* per-router probing (LLDP, HTTP UI
  classification, board.json matching, SSH banner, model-ID resolution) on a
  single device connected to a dedicated probe port. Heavy.
* ``discover.py`` does a *fast* whole-subnet sweep with nmap and returns a
  ranked list of candidates you can pick from a dropdown. It hands off to
  ``conwrt fingerprint`` / ``conwrt auto`` for the deep work on the chosen host.

Usage as CLI:
    python3 scripts/discover.py                       # scan detected subnet
    python3 scripts/discover.py --subnet 192.168.1.0/24
    python3 scripts/discover.py --interface enp3s0 --json
    python3 scripts/discover.py --ports 22,80,443,80,8080 --timeout 20

Usage as module:
    from discover import discover, DiscoveredRouter
    routers = discover(subnet="192.168.1.0/24")
    for r in routers:
        print(r.label, r.ip, r.vendor, r.open_ports)

Design notes:
* nmap is the primary engine (host discovery + ARP MAC + port scan in one
  tool). If nmap is absent, we fall back to a ping sweep + ``ip neigh`` /
  ``arp`` so the module degrades gracefully.
* MAC addresses require root under nmap (raw sockets). When not root, MACs /
  OUI are recovered from the kernel ARP/neighbour table as a fallback.
* Everything network-touching lives behind small, mockable functions so the
  pure-logic core (parsing, scoring, classification) is unit-tested without
  any sockets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# Make sibling scripts/ modules importable (oui, model_match, probe_utils).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from model_match import (  # noqa: E402
    lookup_mac_vendor,
    match_models_by_oui,
)
from oui import oui_lookup  # noqa: E402

# Ports that indicate a router / AP / switch management interface.
DEFAULT_PORTS = [22, 23, 80, 443, 8080, 8081]

# Hosts with any of these ports open are interesting at all.
ROUTER_PORTS = {22, 80, 443, 8080, 8081}

# Subnet prefixes we never want to scan (loopback, link-local, multicast).
SKIP_PREFIXES = ("127.", "169.254.", "224.", "225.", "226.", "0.")


@dataclass
class DiscoveredRouter:
    """One candidate device found on the subnet, dropdown-ready."""

    ip: str
    mac: str = ""
    vendor: str = ""  # MAC OUI vendor (ZyXEL, D-Link, GL.iNet, ...)
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)
    ssh_open: bool = False
    http_open: bool = False
    http_port: int = 0
    http_title: str = ""
    ssh_banner: str = ""
    router_score: int = 0  # 0..100
    likely_router: bool = False
    model_hints: list[str] = field(default_factory=list)
    source: str = ""  # "nmap" | "arp-fallback"

    @property
    def label(self) -> str:
        """Human-friendly label for a dropdown <option>."""
        parts = [self.ip]
        if self.vendor:
            parts.append(self.vendor)
        ports = [str(p) for p in sorted(self.open_ports)]
        if ports:
            parts.append(":" + "/".join(ports))
        if self.mac:
            parts.append(f"({self.mac})")
        return " ".join(parts)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["label"] = self.label
        # Keep open_ports sorted + ints for stable JSON
        d["open_ports"] = sorted(self.open_ports)
        return d


# ---------------------------------------------------------------------------
# Subnet / interface detection
# ---------------------------------------------------------------------------


def detect_local_subnet(interface: Optional[str] = None) -> Optional[str]:
    """Best-effort detection of the local IPv4 subnet in CIDR form.

    Parses ``ip -o -4 addr`` (Linux) or ``ifconfig`` (macOS). When
    ``interface`` is given, restricts to that interface. Returns e.g.
    ``192.168.1.0/24`` or ``None`` if nothing usable is found.
    """
    try:
        out = _run_capture(["ip", "-o", "-4", "addr"], timeout=5)
    except (FileNotFoundError, subprocess.SubprocessError):
        out = ""
    if out:
        for line in out.splitlines():
            # fmt: 13: enp3s0    inet 192.168.1.42/24 brd ...
            m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if not m:
                continue
            ip, prefix = m.group(1), int(m.group(2))
            ifname = line.split()[1] if len(line.split()) > 1 else ""
            if interface and ifname != interface:
                continue
            if ip.startswith(SKIP_PREFIXES):
                continue
            if prefix > 30:  # /31, /32 are not a subnet to sweep
                continue
            return _network_cidr(ip, prefix)
    # macOS fallback
    try:
        out = _run_capture(["ifconfig"], timeout=5)
    except (FileNotFoundError, subprocess.SubprocessError):
        out = ""
    if out:
        cur_iface = None
        for line in out.splitlines():
            if line and not line[0].isspace():
                cur_iface = line.split(":")[0]
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]+)", line)
            if m and (not interface or cur_iface == interface):
                ip = m.group(1)
                mask = _hexmask_to_prefixlen(m.group(2))
                if mask and not ip.startswith(SKIP_PREFIXES) and mask <= 30:
                    return _network_cidr(ip, mask)
    return None


def _network_cidr(ip: str, prefix: int) -> str:
    """Return the network address/prefix for a given ip/prefix (e.g. .0/24)."""
    try:
        octets = [int(x) for x in ip.split(".")]
        ip_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net = ip_int & mask
        return f"{(net >> 24) & 0xFF}.{(net >> 16) & 0xFF}.{(net >> 8) & 0xFF}.{net & 0xFF}/{prefix}"
    except (ValueError, IndexError):
        return f"{ip}/{prefix}"


def _hexmask_to_prefixlen(hexmask: str) -> Optional[int]:
    try:
        val = int(hexmask, 16)
    except ValueError:
        return None
    return bin(val).count("1") if val else None


# ---------------------------------------------------------------------------
# Subprocess helpers (mockable seams)
# ---------------------------------------------------------------------------


def _run_capture(cmd: list[str], timeout: int = 60) -> str:
    """Run a command, return stdout as text. Raises on non-zero? No — returns ''."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            text=True,
        )
        return proc.stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _has_nmap() -> bool:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and Path(d, "nmap").exists():
            return True
    # fall back to actually invoking --version (slower but authoritative)
    return bool(_run_capture(["nmap", "--version"], timeout=8))


# ---------------------------------------------------------------------------
# nmap scan
# ---------------------------------------------------------------------------


def nmap_discover(subnet: str, timeout: int = 60) -> list[dict]:
    """Run an nmap ping-scan for host discovery + MAC, return raw host dicts.

    Uses ``-sn`` (no port scan) + ``-PR`` (ARP) + XML output. MAC/OUI require
    root; when not root the caller recovers MACs from the ARP table.
    """
    xml = _run_capture(
        ["nmap", "-sn", "-PR", "-n", "--disable-arp-ping", "-oX", "-", subnet],
        timeout=timeout,
    )
    return parse_nmap_xml(xml)


def nmap_portscan(hosts: list[str], ports: list[int], timeout: int = 60) -> dict[str, list[int]]:
    """Port-scan a list of IPs; return {ip: [open_ports]}."""
    if not hosts or not ports:
        return {h: [] for h in hosts}
    xml = _run_capture(
        ["nmap", "-p", ",".join(str(p) for p in ports), "-n", "--open", "-oX", "-", *hosts],
        timeout=timeout,
    )
    parsed = parse_nmap_xml(xml)
    result: dict[str, list[int]] = {}
    for host in parsed:
        result[host["ip"]] = [p for p in host.get("open_ports", [])]
    # ensure every requested host is present
    for h in hosts:
        result.setdefault(h, [])
    return result


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML stdout into a list of host dicts.

    Each dict: {ip, mac, vendor, hostname, open_ports}. Robust to empty /
    malformed XML. Pure function — unit-tested directly.
    """
    if not xml_text or "<nmaprun" not in xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    hosts: list[dict] = []
    for h in root.findall("host"):
        # nmap puts host liveness in a <status state="up"/> child, not an
        # attribute of <host>. Hosts without a <status> element are kept.
        status_el = h.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue
        ip = ""
        mac = ""
        vendor = ""
        hostname = ""
        for addr in h.findall("address"):
            addrtype = addr.get("addrtype", "")
            if addrtype == "ipv4":
                ip = addr.get("addr", "")
            elif addrtype == "mac":
                mac = (addr.get("addr", "") or "").lower()
                vendor = addr.get("vendor", "") or ""
        # hostname from <hostnames>
        hn = h.find(".//hostname")
        if hn is not None:
            hostname = hn.get("name", "") or ""
        open_ports: list[int] = []
        for port in h.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                pid = port.get("portid")
                if pid and pid.isdigit():
                    open_ports.append(int(pid))
        # Keep hosts that have an ip, or a mac even without a live port
        if ip or mac:
            hosts.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "open_ports": sorted(set(open_ports)),
                }
            )
    return hosts


# ---------------------------------------------------------------------------
# ARP fallback (no nmap)
# ---------------------------------------------------------------------------


def arp_fallback_scan(subnet: str, ports: list[int], timeout: int = 60) -> list[dict]:
    """Ping-sweep + ARP/neighbour table scan when nmap is unavailable.

    Pings likely hosts in a /24, then reads ``ip neigh`` / ``arp -n`` to map
    IPs to MACs, and probes each port via a plain TCP connect.
    """
    base = _subnet_base(subnet)
    if not base:
        return []
    live_ips = _ping_sweep(base, timeout=timeout)
    ip_mac = _read_neighbour_table()
    hosts: list[dict] = []
    for ip in live_ips:
        mac = ip_mac.get(ip, "")
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": oui_lookup(mac) if mac else "",
                "hostname": _reverse_dns(ip),
                "open_ports": _tcp_probe_ports(ip, ports),
            }
        )
    return hosts


def _subnet_base(subnet: str) -> Optional[str]:
    """Return 'a.b.c' base for a /24-style CIDR, else None."""
    m = re.match(r"^(\d+\.\d+\.\d+)\.\d+/(2[0-4]|1[6-9])$", subnet)
    return m.group(1) if m else None


def _ping_sweep(base: str, timeout: int = 60) -> list[str]:
    """Ping .1...254 in a /24; return responding IPs. Best-effort, fast."""
    live: list[str] = []
    deadline = time.monotonic() + timeout
    for i in range(1, 255):
        if time.monotonic() > deadline:
            break
        ip = f"{base}.{i}"
        if _ping_one(ip):
            live.append(ip)
    return live


def _ping_one(ip: str, timeout: int = 1) -> bool:
    """Single ping; True if the host responds."""
    out = _run_capture(["ping", "-c", "1", "-W", str(timeout), ip], timeout=timeout + 2)
    return "0% packet loss" in out or "1 packets received" in out


def _read_neighbour_table() -> dict[str, str]:
    """Return {ip: mac} from the kernel ARP/neighbour table (Linux/macOS)."""
    table: dict[str, str] = {}
    for cmd in (["ip", "neigh"], ["arp", "-an"]):
        out = _run_capture(cmd, timeout=5)
        if not out:
            continue
        for line in out.splitlines():
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_m = re.search(
                r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|"
                r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})",
                line,
            )
            if ip_m and mac_m:
                table[ip_m.group(1)] = _normalize_mac(mac_m.group(1))
        if table:
            break
    return table


def _tcp_probe_ports(ip: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    """Plain TCP connect to each port; return the open ones."""
    open_ports: list[int] = []
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, p)) == 0:
                    open_ports.append(p)
        except OSError:
            continue
    return sorted(open_ports)


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------------
# Classification + enrichment
# ---------------------------------------------------------------------------


def classify(host: dict) -> DiscoveredRouter:
    """Turn a raw nmap/arp host dict into a scored DiscoveredRouter."""
    ip = host.get("ip", "")
    mac = _normalize_mac(host.get("mac", ""))
    vendor = host.get("vendor") or (oui_lookup(mac) if mac else "") or (lookup_mac_vendor(mac) if mac else "")
    open_ports = sorted(set(int(p) for p in host.get("open_ports", []) if str(p).isdigit()))
    r = DiscoveredRouter(
        ip=ip,
        mac=mac,
        vendor=vendor,
        hostname=host.get("hostname", ""),
        open_ports=open_ports,
        source=host.get("source", "nmap"),
    )
    port_set = set(open_ports)
    r.ssh_open = 22 in port_set
    http_ports = {80, 8080, 8081} & port_set
    https_open = 443 in port_set
    # Any web management port (http or https) is a router signal.
    r.http_open = bool(http_ports or https_open)
    if http_ports:
        r.http_port = min(http_ports)

    score = 0
    if r.http_open:
        score += 40
    if r.ssh_open:
        score += 30
    if vendor and _is_known_networking_vendor(vendor, mac):
        score += 30
    # telnet (23) is a mild router/AP signal too
    if 23 in port_set:
        score += 5
    r.router_score = min(score, 100)
    r.likely_router = (r.router_score >= 50) and bool(port_set & ROUTER_PORTS)
    # model hints from OUI
    if mac:
        try:
            r.model_hints = [m.get("id", "") for m in match_models_by_oui(mac) if m.get("id")]
        except Exception:
            r.model_hints = []
    return r


_KNOWN_VENDOR_TOKENS = (
    "zyxel", "d-link", "dlink", "glinet", "gl.inet", "tp-link", "tplink",
    "asus", "netgear", "linksys", "tenda", "huawei", "xiaomi", "comfast",
    "wrt", "openwrt", "ubiquiti", "mikrotik", "extreme", "nec", "buffalo",
    "belkin", "texas instruments", "qualcomm", "mediatek", "realtek",
    "marvell", "broadcom", "aruba", "intel",
)


def _is_known_networking_vendor(vendor: str, mac: str = "") -> bool:
    """True if the vendor string or OUI looks like networking gear.

    Treats a non-empty OUI lookup result as a positive signal too, since the
    curated oui.py DB only contains router/switch/AP vendors.
    """
    v = vendor.lower()
    if any(tok in v for tok in _KNOWN_VENDOR_TOKENS):
        return True
    if mac and oui_lookup(mac):
        return True
    return False


def enrich(r: DiscoveredRouter, timeout: float = 3.0) -> DiscoveredRouter:
    """Lightly enrich one router: grab HTTP title + SSH banner. Read-only."""
    if r.http_port:
        r.http_title = _http_title(r.ip, r.http_port, timeout=timeout)
        if r.http_title and _title_looks_like_router(r.http_title):
            r.router_score = min(r.router_score + 15, 100)
            r.likely_router = True
    if r.ssh_open:
        r.ssh_banner = _ssh_banner(r.ip, timeout=timeout)
        if _banner_looks_like_router(r.ssh_banner):
            r.router_score = min(r.router_score + 10, 100)
            r.likely_router = True
    return r


def _http_title(ip: str, port: int, timeout: float = 3.0) -> str:
    """Fetch the <title> of http://ip:port/ via curl. Returns '' on failure."""
    out = _run_capture(
        ["curl", "-s", "-m", str(int(timeout)), "--max-time", str(int(timeout)),
         f"http://{ip}:{port}/"],
        timeout=int(timeout) + 2,
    )
    m = re.search(r"<title[^>]*>(.*?)</title>", out, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def _ssh_banner(ip: str, timeout: float = 3.0) -> str:
    """Read the SSH version banner by opening a socket. Returns '' on failure."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, 22))
            banner = s.recv(256).decode("utf-8", errors="replace").strip()
            return banner[:120]
    except OSError:
        return ""


_ROUTER_TITLE_TOKENS = (
    "router", "openwrt", "lede", "web ui", "webui", "admin", "login",
    "setup", "configuration", "dd-wrt", "tomato", "asuswrt", "merlin",
    "switch", "ap ", "access point", "firmware", "ubiquiti", "edgeos",
    "routeros", "routeros", "tenda", "tplink", "tp-link",
)


def _title_looks_like_router(title: str) -> bool:
    t = title.lower()
    return any(tok in t for tok in _ROUTER_TITLE_TOKENS)


def _banner_looks_like_router(banner: str) -> bool:
    b = banner.lower()
    # dropbear/openwrt SSH is a strong router signal
    return "dropbear" in b or "openwrt" in b or "asuswrt" in b


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def discover(
    subnet: Optional[str] = None,
    interface: Optional[str] = None,
    ports: Optional[list[int]] = None,
    timeout: int = 60,
    enrich_hosts: bool = True,
    use_nmap: Optional[bool] = None,
) -> list[DiscoveredRouter]:
    """Scan a subnet and return ranked router candidates.

    Parameters
    ----------
    subnet : CIDR to scan. Auto-detected from the local interface if omitted.
    interface : restrict subnet auto-detection to this interface.
    ports : ports to probe (default DEFAULT_PORTS).
    timeout : overall scan budget in seconds.
    enrich_hosts : if True, grab HTTP title + SSH banner on likely routers.
    use_nmap : force nmap (True) or arp-fallback (False). Auto if None.
    """
    ports = list(ports or DEFAULT_PORTS)
    if not subnet:
        subnet = detect_local_subnet(interface)
    if not subnet:
        raise SystemExit(
            "Could not auto-detect a local subnet. Pass --subnet CIDR or --interface IF."
        )

    if use_nmap is None:
        use_nmap = _has_nmap()

    hosts: list[dict] = []
    if use_nmap:
        hosts = nmap_discover(subnet, timeout=timeout)
        # nmap without root returns no MACs; fill from the ARP table.
        if any(not h.get("mac") for h in hosts):
            neigh = _read_neighbour_table()
            for h in hosts:
                if not h.get("mac") and h.get("ip") in neigh:
                    h["mac"] = neigh[h["ip"]]
        # If host discovery found live IPs but no ports, port-scan them.
        if hosts and not any(h.get("open_ports") for h in hosts):
            portmap = nmap_portscan([h["ip"] for h in hosts if h.get("ip")], ports, timeout=timeout)
            for h in hosts:
                h["open_ports"] = portmap.get(h["ip"], [])
        for h in hosts:
            h["source"] = "nmap"
    else:
        hosts = arp_fallback_scan(subnet, ports, timeout=timeout)
        for h in hosts:
            h["source"] = "arp-fallback"

    routers = [classify(h) for h in hosts]
    # only enrich the ones that look like routers (keeps the sweep fast)
    if enrich_hosts:
        routers = [enrich(r) if r.likely_router else r for r in routers]
    routers.sort(key=lambda r: (-r.router_score, _ip_sort_key(r.ip)))
    return routers


def _ip_sort_key(ip: str) -> tuple:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_table(routers: list[DiscoveredRouter]) -> str:
    """Render a compact human-readable table to stdout text."""
    if not routers:
        return "No hosts found."
    header = f"{'IP':<16}{'MAC':<19}{'VENDOR':<14}{'PORTS':<20}{'SCORE':>5}  TITLE"
    lines = [header, "-" * len(header)]
    for r in routers:
        mark = "*" if r.likely_router else " "
        ports = "/".join(str(p) for p in sorted(r.open_ports)) or "-"
        title = r.http_title or r.ssh_banner or ""
        lines.append(
            f"{mark}{r.ip:<15}{r.mac:<19}{r.vendor[:13]:<14}{ports:<20}{r.router_score:>4}% {title[:40]}"
        )
    lines.append("")
    lines.append(f"{len(routers)} host(s); {sum(1 for r in routers if r.likely_router)} likely router(s) (*).")
    lines.append("Pick one and run:  conwrt fingerprint <IP>   |   conwrt auto --interface <IF>")
    return "\n".join(lines)


def to_json(routers: list[DiscoveredRouter]) -> str:
    """Dropdown-ready JSON array."""
    return json.dumps([r.to_dict() for r in routers], indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _normalize_mac(mac: str) -> str:
    """Lowercase + colon-separate any MAC form (aa:bb:.., aa-bb-.., aabb.ccdd..)."""
    if not mac:
        return ""
    hexes = re.findall(r"[0-9a-fA-F]{2}", mac)
    if len(hexes) != 6:
        return mac.lower()
    return ":".join(h.lower() for h in hexes)


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="discover",
        description="Auto-discover routers on the local subnet (nmap + ARP + MAC OUI).",
    )
    p.add_argument("--subnet", default=None, help="CIDR to scan (e.g. 192.168.1.0/24). Auto-detected if omitted.")
    p.add_argument("--interface", default=None, help="Restrict subnet auto-detection to this interface.")
    p.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS),
                   help=f"Comma-separated ports to probe (default: {DEFAULT_PORTS}).")
    p.add_argument("--timeout", type=int, default=60, help="Overall scan budget in seconds (default 60).")
    p.add_argument("--json", action="store_true", dest="json_output", help="Output dropdown-ready JSON.")
    p.add_argument("--no-enrich", action="store_true", help="Skip HTTP title / SSH banner enrichment (faster).")
    p.add_argument("--min-score", type=int, default=0, help="Only show routers scoring >= this (0-100).")
    p.add_argument("--no-nmap", action="store_true", help="Force ARP/ping fallback instead of nmap.")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_argparser().parse_args(argv)
    try:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    except ValueError:
        ports = list(DEFAULT_PORTS)

    routers = discover(
        subnet=args.subnet,
        interface=args.interface,
        ports=ports,
        timeout=args.timeout,
        enrich_hosts=not args.no_enrich,
        use_nmap=False if args.no_nmap else None,
    )
    if args.min_score:
        routers = [r for r in routers if r.router_score >= args.min_score]

    if args.json_output:
        print(to_json(routers))
    else:
        if not args.subnet and not args.interface:
            print(f"[discover] scanning auto-detected subnet...", file=sys.stderr)
        print(format_table(routers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
