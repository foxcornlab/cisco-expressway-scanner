"""Tests for expressway_scanner.py.

Everything runs against local mocks: a fake Expressway login page on
localhost, TCP listeners standing in for the cluster database ports,
and synthetic erlang.log bundles. No real Expressway is touched.
"""

import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import expressway_scanner as scanner

# ---------------------------------------------------------------- version

GRADE_CASES = [
    # (version string, expected verdict)
    ("X15.5.3", "VULNERABLE"),    # the release F6's victims ran
    ("X15.3.2", "VULNERABLE"),    # the release the public PoC validated on
    ("X15.5.19", "VULNERABLE"),   # one patch behind the fix
    ("X15.5.2", "VULNERABLE"),
    ("X15.0", "VULNERABLE"),
    ("X15", "VULNERABLE"),
    ("15.5.3", "VULNERABLE"),     # bare version, no X marker
    ("x15.5.3", "VULNERABLE"),    # lowercase x
    ("X14.0", "VULNERABLE"),      # no fix on the X14 line, must migrate
    ("X12.7", "VULNERABLE"),
    ("X8.11.4", "VULNERABLE"),    # bottom of the affected range
    ("X15.5.20", "FIXED"),        # first fixed release per Cisco
    ("X15.5.21", "FIXED"),
    ("X15.5.22", "FIXED"),
    ("X15.6.0", "FIXED"),
    ("X16.0", "UNKNOWN"),         # newer than the advisory table
    ("banana", "UNKNOWN"),
    ("", "UNKNOWN"),
]


@pytest.mark.parametrize("raw,expected", GRADE_CASES)
def test_grade_versions(raw, expected):
    verdict, _detail = scanner.grade(scanner.parse_version(raw))
    assert verdict == expected, raw


def test_grade_none_is_unknown():
    assert scanner.grade(None)[0] == "UNKNOWN"


def test_x15_5_3_trap_names_the_other_cve():
    _verdict, detail = scanner.grade(scanner.parse_version("X15.5.3"))
    assert "76435" in detail  # the MRA flaw X15.5.3 does fix


def test_x14_trap_says_migrate():
    _verdict, detail = scanner.grade(scanner.parse_version("X14.0"))
    assert "migrate" in detail


def test_standalone_is_not_exposed_but_still_warned():
    verdict, detail = scanner.grade(
        scanner.parse_version("X15.5.3"), clustered=False)
    assert verdict == "NOT_EXPOSED"
    assert "76490" in detail  # the hardening set still applies


def test_standalone_fixed_is_fixed():
    verdict, _detail = scanner.grade(
        scanner.parse_version("X15.5.20"), clustered=False)
    assert verdict == "FIXED"


# ------------------------------------------------------- version extraction


def test_extract_version_prefers_version_line():
    text = (
        "Cisco Expressway\n"
        "Some release notes mention X12.7 in passing.\n"
        "Software version: X15.5.3\n"
    )
    version, token = scanner.extract_version(text)
    assert version == (15, 5, 3)
    assert token == "X15.5.3"


def test_extract_version_falls_back_to_first_token():
    text = "Cisco Expressway X15.3.2 login"
    version, token = scanner.extract_version(text)
    assert version == (15, 3, 2)
    assert token == "X15.3.2"


def test_extract_version_ignores_years():
    version, _token = scanner.extract_version("Copyright 2026 Cisco")
    assert version is None


# ------------------------------------------------------------ mock HTTP page

EXPRESSWAY_PAGE = """<!DOCTYPE html>
<html><head><title>Cisco Expressway - Login</title></head>
<body>
<h1>Cisco Expressway</h1>
<form>...</form>
<div class="footer">Software version X15.5.3</div>
</body></html>
"""

EXPRESSWAY_PAGE_NO_VERSION = """<!DOCTYPE html>
<html><head><title>Cisco Expressway - Login</title></head>
<body><h1>Cisco Expressway</h1></body></html>
"""

NOT_EXPRESSWAY_PAGE = """<!DOCTYPE html>
<html><head><title>Some other box</title></head>
<body><h1>Hello</h1></body></html>
"""


def _make_server(body):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_probe_url_vulnerable_version_and_open_ports():
    server = _make_server(EXPRESSWAY_PAGE)
    try:
        # Stand in for 4371/4372 with two listeners on free ports.
        port_a, port_b = _free_port(), _free_port()
        sock_a = socket.socket()
        sock_a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_a.bind(("127.0.0.1", port_a))
        sock_a.listen(1)
        sock_b = socket.socket()
        sock_b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_b.bind(("127.0.0.1", port_b))
        sock_b.listen(1)
        try:
            base = "http://127.0.0.1:%d" % server.server_address[1]
            result = scanner.probe_url(
                base, cluster_ports=(port_a, port_b))
        finally:
            sock_a.close()
            sock_b.close()
    finally:
        server.shutdown()
        server.server_close()
    assert result["is_expressway"] is True
    assert result["version"] == "X15.5.3"
    assert result["verdict"] == "VULNERABLE"
    assert all(info["reachable"]
               for info in result["cluster_ports"].values())
    assert "4371" in result["detail"] or "restrict" in result["detail"]


def test_probe_url_closed_cluster_ports_still_vulnerable():
    server = _make_server(EXPRESSWAY_PAGE)
    try:
        base = "http://127.0.0.1:%d" % server.server_address[1]
        result = scanner.probe_url(
            base, cluster_ports=(_free_port(), _free_port()))
    finally:
        server.shutdown()
        server.server_close()
    assert result["verdict"] == "VULNERABLE"
    assert all(not info["reachable"]
               for info in result["cluster_ports"].values())
    assert "not reachable" in result["detail"]


def test_probe_url_no_version_is_unknown():
    server = _make_server(EXPRESSWAY_PAGE_NO_VERSION)
    try:
        base = "http://127.0.0.1:%d" % server.server_address[1]
        result = scanner.probe_url(base)
    finally:
        server.shutdown()
        server.server_close()
    assert result["is_expressway"] is True
    assert result["verdict"] == "UNKNOWN"


def test_probe_url_not_expressway():
    server = _make_server(NOT_EXPRESSWAY_PAGE)
    try:
        base = "http://127.0.0.1:%d" % server.server_address[1]
        result = scanner.probe_url(base)
    finally:
        server.shutdown()
        server.server_close()
    assert result["verdict"] == "NOT_EXPRESSWAY"


def test_probe_url_unreachable():
    result = scanner.probe_url("http://127.0.0.1:1")
    assert result["verdict"] == "UNKNOWN"
    assert "unreachable" in result["detail"]


# ------------------------------------------------------------------ --local

ERLANG_LOG_VULN = """2026-11-19T02:14:03Z [erlang] nodeup,'wombat@127.0.0.1'
2026-11-19T02:14:04Z [cm_server] cluster peer connected
2026-11-19T02:15:11Z [shell] spawned /mnt/harddisk/i1234a/scan.py
2026-11-19T02:16:00Z [net] connection from 66.179.31.32
"""

ERLANG_LOG_CLEAN = """2026-11-20T09:00:00Z [cm_server] cluster peer connected
2026-11-20T09:00:01Z [erlang] nodeup,'expressway1@10.0.0.5'
SystemUnit Software Version: X15.5.20
"""

VERSION_FILE = "Cisco Expressway\nSoftware version X15.5.3\n"


def test_local_vuln_log_with_iocs(tmp_path):
    log = tmp_path / "erlang.log"
    log.write_text(ERLANG_LOG_VULN + "Software Version: X15.5.3\n")
    result = scanner.read_local(str(log))
    assert result["verdict"] == "VULNERABLE"
    assert result["version"] == "X15.5.3"
    kinds = [hit["kind"] for hit in result["ioc_hits"]]
    assert any("wombat" in kind for kind in kinds)
    assert any("66.179.31.32" in kind for kind in kinds)
    assert any("mnt/harddisk" in kind for kind in kinds)


def test_local_fixed_version_clean_logs(tmp_path):
    log = tmp_path / "erlang.log"
    log.write_text(ERLANG_LOG_CLEAN)
    result = scanner.read_local(str(log))
    assert result["version"] == "X15.5.20"
    assert result["verdict"] == "FIXED"
    assert result["ioc_hits"] == []


def test_local_second_ioc_ip(tmp_path):
    log = tmp_path / "erlang.log"
    log.write_text("connection from 18.130.47.116\nSoftware Version: X15.5.3\n")
    result = scanner.read_local(str(log))
    assert any("18.130.47.116" in hit["kind"]
               for hit in result["ioc_hits"])


def test_local_relay_lock_deny(tmp_path):
    relay = tmp_path / "relay.log"
    relay.write_text("2026-11-19 relay: LOCK denied for peer\n"
                     "Software Version: X15.5.3\n")
    result = scanner.read_local(str(tmp_path))
    assert any("relay log" in hit["kind"] for hit in result["ioc_hits"])


def test_local_devshm_pylibs(tmp_path):
    log = tmp_path / "erlang.log"
    log.write_text("loading /dev/shm/pylibs/scan.py\n"
                   "Software Version: X15.5.3\n")
    result = scanner.read_local(str(log))
    assert any("pylibs" in hit["kind"] for hit in result["ioc_hits"])


def test_local_missing_path(tmp_path):
    result = scanner.read_local(str(tmp_path / "nope"))
    assert result["verdict"] == "UNKNOWN"
    assert "does not exist" in result["detail"]


def test_local_version_file_only(tmp_path):
    version_file = tmp_path / "version.txt"
    version_file.write_text(VERSION_FILE)
    result = scanner.read_local(str(version_file))
    assert result["version"] == "X15.5.3"
    assert result["verdict"] == "VULNERABLE"


# -------------------------------------------------------------- inventory

def test_inventory_json(tmp_path, capsys):
    inventory = tmp_path / "fleet.json"
    inventory.write_text(json.dumps([
        {"host": "exp-e-1", "version": "X15.5.3"},
        {"host": "exp-e-2", "version": "X15.5.20"},
        {"host": "exp-c-1", "version": "X14.0"},
    ]))
    code = scanner.main(["--inventory-json", str(inventory)])
    out = capsys.readouterr().out
    assert code == 1
    assert "VULNERABLE: 2" in out
    assert "FIXED: 1" in out


def test_inventory_json_output(tmp_path, capsys):
    inventory = tmp_path / "fleet.json"
    inventory.write_text(json.dumps([
        {"host": "exp-e-1", "version": "X15.5.3"},
    ]))
    code = scanner.main(["--inventory-json", str(inventory), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data[0]["verdict"] == "VULNERABLE"


# ------------------------------------------------------------------- CLI

def test_cli_version_exit_codes(capsys):
    assert scanner.main(["--version", "X15.5.20"]) == 0
    assert scanner.main(["--version", "X15.5.3"]) == 1
    assert scanner.main(["--version", "banana"]) == 2
    assert scanner.main(["--version", "X15.5.3", "--standalone"]) == 0


def test_cli_list(capsys):
    assert scanner.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "X15.5.20" in out
    assert "CVE-2026-76466" in out
    assert "2026-11-23" in out


def test_cli_list_json(capsys):
    assert scanner.main(["--list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["cve"] == "CVE-2026-76466"
    assert data["fixed"]["Expressway X15.5.3 and earlier"] == \
        "X15.5.20 (or later)"


def test_cli_requires_exactly_one_mode():
    with pytest.raises(SystemExit):
        scanner.main([])
    with pytest.raises(SystemExit):
        scanner.main(["--version", "X15.5.3", "--url", "https://x"])
