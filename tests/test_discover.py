"""Tests for scripts/discover.py — subnet auto-discovery (nmap + ARP + MAC OUI).

The pure-logic core (nmap XML parsing, classification scoring, CIDR math, MAC
normalization, JSON/table rendering, orchestration) is tested directly. The
network-touching seams (_run_capture, _ping_one, _tcp_probe_ports,
_read_neighbour_table, nmap_discover) are monkeypatched so no sockets or
subprocesses are opened.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import discover  # noqa: E402
from discover import (  # noqa: E402
    DEFAULT_PORTS,
    DiscoveredRouter,
    _banner_looks_like_router,
    _hexmask_to_prefixlen,
    _is_known_networking_vendor,
    _network_cidr,
    _normalize_mac,
    _subnet_base,
    _title_looks_like_router,
    arp_fallback_scan,
    build_argparser,
    classify,
    discover,
    format_table,
    main,
    nmap_discover,
    parse_nmap_xml,
    to_json,
)


# ---------------------------------------------------------------------------
# nmap XML parsing
# ---------------------------------------------------------------------------

NMAP_SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn">
  <host><status state="down" reason="no-response"/><address addr="192.168.1.2" addrtype="ipv4"/></host>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="D8:5D:84:11:22:33" addrtype="mac" vendor="ZyXEL Communications Corp."/>
    <hostnames><hostname name="router.lan" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
      <port protocol="tcp" portid="80"><state state="open"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/></port>
    </ports>
  </host>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <address addr="a4:bb:cc:00:11:22" addrtype="mac" vendor="Unknown Vendor"/>
  </host>
</nmaprun>"""


class TestParseNmapXml:
    def test_parses_up_hosts_only(self):
        hosts = parse_nmap_xml(NMAP_SAMPLE)
        ips = [h["ip"] for h in hosts]
        assert "192.168.1.1" in ips
        assert "192.168.1.50" in ips
        assert "192.168.1.2" not in ips  # down host excluded

    def test_extracts_mac_vendor_hostname(self):
        hosts = {h["ip"]: h for h in parse_nmap_xml(NMAP_SAMPLE)}
        h = hosts["192.168.1.1"]
        assert h["mac"] == "d8:5d:84:11:22:33"
        assert h["vendor"] == "ZyXEL Communications Corp."
        assert h["hostname"] == "router.lan"

    def test_extracts_open_ports_only(self):
        hosts = {h["ip"]: h for h in parse_nmap_xml(NMAP_SAMPLE)}
        assert hosts["192.168.1.1"]["open_ports"] == [22, 80]
        assert hosts["192.168.1.50"]["open_ports"] == []

    def test_empty_and_malformed(self):
        assert parse_nmap_xml("") == []
        assert parse_nmap_xml("not xml at all") == []
        assert parse_nmap_xml("<nmaprun></nmaprun>") == []
        assert parse_nmap_xml("garbage <nmaprun><host") == []

    def test_host_with_mac_but_no_ip_kept(self):
        xml = '<nmaprun><host><status state="up"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="X"/></host></nmaprun>'
        hosts = parse_nmap_xml(xml)
        assert len(hosts) == 1
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:ff"


# ---------------------------------------------------------------------------
# MAC normalization + CIDR math
# ---------------------------------------------------------------------------

class TestNormalizeMac:
    def test_colon_form(self):
        assert _normalize_mac("D8:5D:84:11:22:33") == "d8:5d:84:11:22:33"

    def test_dash_form(self):
        assert _normalize_mac("d8-5d-84-11-22-33") == "d8:5d:84:11:22:33"

    def test_cisco_form(self):
        assert _normalize_mac("d85d.8411.2233") == "d8:5d:84:11:22:33"

    def test_empty(self):
        assert _normalize_mac("") == ""
        assert _normalize_mac(None) == ""  # type: ignore[arg-type]


class TestCidrMath:
    def test_network_address(self):
        assert _network_cidr("192.168.1.42", 24) == "192.168.1.0/24"
        assert _network_cidr("10.0.5.100", 16) == "10.0.0.0/16"
        assert _network_cidr("172.16.30.7", 8) == "172.0.0.0/8"

    def test_hexmask(self):
        assert _hexmask_to_prefixlen("ffffff00") == 24
        assert _hexmask_to_prefixlen("ffff0000") == 16
        assert _hexmask_to_prefixlen("0") is None
        assert _hexmask_to_prefixlen("nothex") is None

    def test_subnet_base(self):
        assert _subnet_base("192.168.1.0/24") == "192.168.1"
        assert _subnet_base("10.0.0.0/16") == "10.0.0"  # /16-/24 supported
        assert _subnet_base("10.0.0.0/8") is None  # too wide


# ---------------------------------------------------------------------------
# Classification scoring
# ---------------------------------------------------------------------------

class TestClassify:
    def test_router_with_ssh_http_known_vendor(self):
        h = {"ip": "192.168.1.1", "mac": "d8:5d:84:11:22:33",
             "open_ports": [22, 80], "vendor": "ZyXEL"}
        r = classify(h)
        assert r.ssh_open
        assert r.http_open
        assert r.http_port == 80
        assert r.router_score >= 50
        assert r.likely_router is True
        assert r.vendor  # resolved

    def test_https_counts(self):
        h = {"ip": "192.168.1.1", "open_ports": [443], "vendor": "TP-Link"}
        r = classify(h)
        # https counts as web management (+40) + known vendor (+30) = 70
        assert r.router_score == 70
        assert r.http_open is True
        assert r.likely_router is True

    def test_unknown_host_no_router_ports(self):
        h = {"ip": "192.168.1.99", "open_ports": [], "mac": "aa:bb:cc:dd:ee:ff"}
        r = classify(h)
        assert r.router_score == 0
        assert r.likely_router is False

    def test_telnet_only_low_score(self):
        h = {"ip": "192.168.1.5", "open_ports": [23], "vendor": "Random Co"}
        r = classify(h)
        assert r.router_score == 5  # telnet only, unknown vendor
        assert r.likely_router is False  # 5 < 50

    def test_vendor_from_oui_when_nmap_blank(self):
        # nmap without root returns no vendor; classify fills from oui_lookup
        h = {"ip": "192.168.1.1", "mac": "d8:5d:84:11:22:33",
             "open_ports": [80], "vendor": ""}
        r = classify(h)
        assert r.vendor  # filled from OUI DB

    def test_model_hints_from_oui(self):
        h = {"ip": "192.168.1.1", "mac": "d8:5d:84:11:22:33", "open_ports": [80]}
        r = classify(h)
        assert isinstance(r.model_hints, list)

    def test_score_capped_at_100(self):
        h = {"ip": "1.2.3.4", "open_ports": [22, 80, 443, 8080, 23], "vendor": "ZyXEL",
             "mac": "d8:5d:84:11:22:33"}
        r = classify(h)
        assert r.router_score == 100


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

class TestHeuristics:
    def test_known_vendor(self):
        assert _is_known_networking_vendor("ZyXEL")
        assert _is_known_networking_vendor("TP-Link Technologies")
        assert not _is_known_networking_vendor("Totally Unknown Co")

    def test_known_vendor_via_mac_oui(self):
        assert _is_known_networking_vendor("", "d8:5d:84:11:22:33")
        assert not _is_known_networking_vendor("", "aa:bb:cc:dd:ee:ff")

    def test_title_router_detection(self):
        assert _title_looks_like_router("OpenWrt Administration")
        assert _title_looks_like_router("TP-Link Router Login")
        assert not _title_looks_like_router("Personal Blog - Home")

    def test_banner_router_detection(self):
        assert _banner_looks_like_router("SSH-2.0-dropbear")
        assert not _banner_looks_like_router("SSH-2.0-openssh Ubuntu")


# ---------------------------------------------------------------------------
# Dataclass + rendering
# ---------------------------------------------------------------------------

class TestRendering:
    def test_label_includes_ports_and_vendor(self):
        r = DiscoveredRouter(ip="10.0.0.1", vendor="ZyXEL", open_ports=[22, 80],
                             mac="d8:5d:84:11:22:33")
        lbl = r.label
        assert "10.0.0.1" in lbl
        assert "ZyXEL" in lbl
        assert "22/80" in lbl

    def test_to_dict_has_label_and_sorted_ports(self):
        r = DiscoveredRouter(ip="1.2.3.4", open_ports=[80, 22])
        d = r.to_dict()
        assert d["label"]
        assert d["open_ports"] == [22, 80]

    def test_to_json_is_valid_array(self):
        routers = [DiscoveredRouter(ip="1.2.3.4", vendor="X", open_ports=[22])]
        data = json.loads(to_json(routers))
        assert isinstance(data, list)
        assert data[0]["ip"] == "1.2.3.4"
        assert data[0]["label"]

    def test_format_table_empty(self):
        assert "No hosts" in format_table([])

    def test_format_table_populated(self):
        routers = [DiscoveredRouter(ip="1.2.3.4", vendor="ZyXEL", open_ports=[22, 80],
                                    router_score=70, likely_router=True)]
        out = format_table(routers)
        assert "1.2.3.4" in out
        assert "ZyXEL" in out
        assert "*" in out  # likely-router marker
        assert "likely router" in out


# ---------------------------------------------------------------------------
# nmap discovery + ARP fallback (mocked subprocess seams)
# ---------------------------------------------------------------------------

class TestNmapDiscover:
    def test_nmap_discover_parses_xml(self):
        with patch("discover._run_capture", return_value=NMAP_SAMPLE):
            hosts = nmap_discover("192.168.1.0/24")
        ips = [h["ip"] for h in hosts]
        assert "192.168.1.1" in ips
        assert "192.168.1.50" in ips

    def test_nmap_discover_empty_on_failure(self):
        with patch("discover._run_capture", return_value=""):
            assert nmap_discover("192.168.1.0/24") == []


class TestArpFallback:
    def test_arp_fallback_scan_combines(self):
        with patch("discover._ping_sweep", return_value=["192.168.1.1", "192.168.1.2"]), \
             patch("discover._read_neighbour_table",
                   return_value={"192.168.1.1": "d8:5d:84:11:22:33"}), \
             patch("discover._tcp_probe_ports", side_effect=[[22, 80], []]), \
             patch("discover._reverse_dns", return_value=""):
            hosts = arp_fallback_scan("192.168.1.0/24", [22, 80], timeout=5)
        by_ip = {h["ip"]: h for h in hosts}
        assert by_ip["192.168.1.1"]["mac"] == "d8:5d:84:11:22:33"
        assert by_ip["192.168.1.1"]["vendor"]  # OUI resolved
        assert by_ip["192.168.1.1"]["open_ports"] == [22, 80]
        assert by_ip["192.168.1.2"]["open_ports"] == []


# ---------------------------------------------------------------------------
# Orchestration: discover() sorts, enriches only likely routers, fills MACs
# ---------------------------------------------------------------------------

class TestDiscoverOrchestration:
    def test_sort_by_score_desc(self):
        fake_hosts = [
            {"ip": "192.168.1.99", "open_ports": [], "mac": "aa:bb:cc:dd:ee:ff"},
            {"ip": "192.168.1.1", "open_ports": [22, 80], "vendor": "ZyXEL",
             "mac": "d8:5d:84:11:22:33"},
        ]
        with patch("discover._has_nmap", return_value=True), \
             patch("discover.nmap_discover", return_value=fake_hosts), \
             patch("discover.enrich", side_effect=lambda r, **k: r):
            routers = discover(subnet="192.168.1.0/24", enrich_hosts=True)
        assert routers[0].ip == "192.168.1.1"
        assert routers[0].router_score >= routers[1].router_score

    def test_enrich_only_called_on_likely_routers(self):
        likely = {"ip": "1.1.1.1", "open_ports": [22, 80], "vendor": "ZyXEL",
                  "mac": "d8:5d:84:11:22:33"}
        other = {"ip": "1.1.1.2", "open_ports": [], "mac": "aa:bb:cc:dd:ee:ff"}
        with patch("discover._has_nmap", return_value=True), \
             patch("discover.nmap_discover", return_value=[likely, other]), \
             patch("discover.enrich", side_effect=lambda r, **k: r) as mock_enrich:
            routers = discover(subnet="192.168.1.0/24", enrich_hosts=True)
        # enrich called exactly once (only on the likely router)
        assert mock_enrich.call_count == 1
        enriched = mock_enrich.call_args[0][0]
        assert enriched.likely_router is True

    def test_mac_filled_from_neighbour_table_when_missing(self):
        host_no_mac = {"ip": "192.168.1.1", "open_ports": [22, 80], "mac": ""}
        with patch("discover._has_nmap", return_value=True), \
             patch("discover.nmap_discover", return_value=[host_no_mac]), \
             patch("discover._read_neighbour_table",
                   return_value={"192.168.1.1": "d8:5d:84:11:22:33"}):
            routers = discover(subnet="192.168.1.0/24", enrich_hosts=False)
        assert routers[0].mac == "d8:5d:84:11:22:33"

    def test_portscan_runs_when_discovery_found_no_ports(self):
        host = {"ip": "192.168.1.1", "open_ports": [], "mac": "d8:5d:84:11:22:33"}
        with patch("discover._has_nmap", return_value=True), \
             patch("discover.nmap_discover", return_value=[host]), \
             patch("discover.nmap_portscan",
                   return_value={"192.168.1.1": [22, 80]}) as mock_ps:
            routers = discover(subnet="192.168.1.0/24", enrich_hosts=False)
        mock_ps.assert_called_once()
        assert routers[0].open_ports == [22, 80]

    def test_no_subnet_raises(self):
        with patch("discover.detect_local_subnet", return_value=None):
            with pytest.raises(SystemExit):
                discover(subnet=None)

    def test_arp_fallback_used_when_no_nmap(self):
        with patch("discover._has_nmap", return_value=False), \
             patch("discover.arp_fallback_scan",
                   return_value=[{"ip": "1.1.1.1", "open_ports": [80], "mac": ""}]):
            routers = discover(subnet="192.168.1.0/24", enrich_hosts=False)
        assert len(routers) == 1
        assert routers[0].source == "arp-fallback"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCli:
    def test_json_output(self, capsys):
        fake = [DiscoveredRouter(ip="1.2.3.4", vendor="ZyXEL", open_ports=[22, 80],
                                 router_score=70, likely_router=True)]
        with patch("discover.discover", return_value=fake):
            rc = main(["--subnet", "1.2.3.0/24", "--json"])
        out = capsys.readouterr().out
        assert rc == 0
        data = json.loads(out)
        assert data[0]["ip"] == "1.2.3.4"
        assert data[0]["label"]

    def test_table_output(self, capsys):
        fake = [DiscoveredRouter(ip="1.2.3.4", vendor="ZyXEL", open_ports=[22])]
        with patch("discover.discover", return_value=fake):
            rc = main(["--subnet", "1.2.3.0/24"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "1.2.3.4" in out
        assert "likely router" in out or "host" in out

    def test_min_score_filter(self, capsys):
        routers = [
            DiscoveredRouter(ip="1.1.1.1", router_score=80, open_ports=[22, 80]),
            DiscoveredRouter(ip="1.1.1.2", router_score=10, open_ports=[]),
        ]
        with patch("discover.discover", return_value=routers):
            main(["--subnet", "1.2.3.0/24", "--json", "--min-score", "50"])
        data = json.loads(capsys.readouterr().out)
        assert len(data) == 1
        assert data[0]["ip"] == "1.1.1.1"

    def test_argparser_defaults(self):
        p = build_argparser()
        args = p.parse_args([])
        assert args.timeout == 60
        assert args.json_output is False
        assert args.subnet is None

    def test_ports_default_parsed(self, capsys):
        with patch("discover.discover", return_value=[]) as mock_d:
            main(["--subnet", "1.2.3.0/24", "--json"])
        _, kwargs = mock_d.call_args
        assert kwargs["ports"] == DEFAULT_PORTS


# ---------------------------------------------------------------------------
# cmd_discover wrapper (conwrt CLI integration)
# ---------------------------------------------------------------------------

class TestCmdDiscover:
    def test_cmd_discover_json(self, capsys):
        from conwrt.cmd_discover import cmd_discover
        fake = [DiscoveredRouter(ip="1.2.3.4", vendor="ZyXEL", open_ports=[22, 80],
                                 router_score=70, likely_router=True)]
        args = SimpleNamespace(subnet="1.2.3.0/24", interface=None, ports="22,80",
                               timeout=60, json_output=True, no_enrich=False,
                               min_score=0, no_nmap=False)
        with patch("discover.discover", return_value=fake):
            rc = cmd_discover(args)
        data = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert data[0]["ip"] == "1.2.3.4"
