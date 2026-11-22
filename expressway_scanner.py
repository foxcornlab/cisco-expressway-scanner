#!/usr/bin/env python3
"""Detection-only triage for Cisco Expressway CVE-2026-76466.

Unauthenticated remote code execution as root in the cluster database
service of clustered Cisco Expressway-C and Expressway-E. The service
runs on Erlang/OTP and uses persistent cookies: the cluster nodes share
a hard-coded cookie, and when TLS Verify Mode is set to Enabled for
clustering, client certificates are not validated. An unauthenticated
remote attacker with network access who holds the cookies can connect
to the database service, invoke RPC commands, and run operating-system
commands as root on the box. CVSS 3.1 9.8
(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), CWE-798.
Cisco patched it 2026-10-21 in advisory cisco-sa-vcs-static-cred-hr7EWZ8t
(reported by Stefan Aleksic of Jane Street). F6 reported the first
in-the-wild exploitation on 2026-11-19: two internet-facing
Expressway-E nodes running X15.5.3 at an unnamed Russian organisation,
then a pivot to two internal cluster nodes, then custom Python scripts
for lateral movement (SMB, SQL Server, WinRM, GitLab credential
hunting). CISA added it to KEV on 2026-11-20, due 2026-11-23.

Detection only. This scanner never opens the Erlang distribution
service, never sends the hard-coded cookie, never completes an Erlang
handshake, and never invokes an RPC call. A public PoC (dinosn, 12 Nov)
ships a fleet detector whose ping mode authenticates to the cluster
service — that is live-exposure proof, and it is also exploit-adjacent
traffic this tool deliberately does not send. What this tool does
instead is version-table grading against Cisco's own fixed release,
plus reading the logs your box already wrote for the compromise signs
F6 published. The only thing it asks a remote Expressway for is one
plain HTTPS GET of its login page, and two bare TCP connects to the
cluster database ports (4371/4372) that send no bytes at all.

Fixed releases, per Cisco advisory cisco-sa-vcs-static-cred-hr7EWZ8t
(primary source):

    Expressway X15.5.3 and earlier -> X15.5.20 (or later)
    Expressway X14 and earlier     -> migrate to a fixed release
    TelePresence VCS                -> no fix, end of life

There is no workaround. Patching is the only fix, and patching alone
is not enough if the box was already hit: F6's intrusion staged Python
under /mnt/harddisk and went after GitLab credentials, so rotate
credentials and hunt for the compromise signs (`--local` checks the
ones F6 published).
"""

import argparse
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

CVE_MAIN = "CVE-2026-76466"
CVSS = "9.8"
CWE = "CWE-798"
ADVISORY = "cisco-sa-vcs-static-cred-hr7EWZ8t"
KEV_DUE = "2026-11-23"

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_UNKNOWN = 2
EXIT_USAGE = 3

# First fixed release, per the Cisco advisory. Everything in the X15
# line below this is vulnerable; X14 and earlier have no fix on their
# own line at all and must migrate to it.
FIXED_VERSION = (15, 5, 20)
FIXED_LABEL = "X15.5.20"

# Erlang distribution ports for the cluster database service. F6's
# interim mitigation is to block these at the firewall except between
# trusted cluster nodes. A bare connect sends no bytes.
CLUSTER_PORTS = (4371, 4372)

# A version token anywhere in text: "X15.5.3", "X15.3.2", "X14.0",
# even a bare "X15". The leading X is the Expressway release marker;
# bare "15.5.3" is accepted too and normalised on parse.
VERSION_TOKEN = re.compile(r"\bX?(\d+)(?:\.(\d+))?(?:\.(\d+))?\b")

# Compromise signs published by F6 (via the 2026-11-19/20 reporting)
# and the follow-on write-ups. One hit per line is enough.
IOC_PATTERNS = (
    ("wombat nodeup in erlang.log (F6 key indicator)",
     re.compile(r"wombat@\S+", re.IGNORECASE)),
    ("F6 IOC IP 66.179.31.32", re.compile(r"66\.179\.31\.32")),
    ("F6 IOC IP 18.130.47.116", re.compile(r"18\.130\.47\.116")),
    ("staged Python under /mnt/harddisk (F6)",
     re.compile(r"/mnt/harddisk/\S*\.py", re.IGNORECASE)),
    ("staged files under /dev/shm/pylibs (F6)",
     re.compile(r"/dev/shm/pylibs", re.IGNORECASE)),
    ("staged files under /dev/shm", re.compile(r"/dev/shm/\S+\.py",
                                                re.IGNORECASE)),
)

# F6 also flags LOCK and DENY entries in the relay logs. Those words
# are too common to grep in every log, so this pattern only runs over
# files whose name says "relay".
RELAY_IOC = re.compile(r"\b(LOCK|DENY)\b")

MAX_LOG_BYTES = 50 * 1024 * 1024  # per file, so a giant log cannot OOM us


def parse_version(raw):
    """Parse "X15.5.3" (or "15.5.3", "x15.3.2") into (15, 5, 3).

    Returns None when the string carries no version token at all.
    Missing components default to 0, so "X14" means (14, 0, 0).
    """
    if raw is None:
        return None
    match = VERSION_TOKEN.search(raw.strip())
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def fmt_version(version):
    """Render a version tuple as Expressway writes it: X15.5.3."""
    return "X%d.%d.%d" % version


def grade(version, clustered=True):
    """Grade a parsed version tuple.

    Returns (verdict, detail) with verdict VULNERABLE, FIXED,
    NOT_EXPOSED or UNKNOWN. `clustered=False` means the operator has
    declared the box standalone: this flaw needs a cluster, so a
    standalone box is not exposed to this CVE — but it is still
    exposed to the October 2026 hardening set (CVE-2026-76490
    through CVE-2026-76497, up to 8.6) when it sits below X15.5.20,
    and the detail says so. The default assumes clustered, because
    guessing "standalone" would under-report the risk.
    """
    if version is None:
        return "UNKNOWN", "no parseable version"

    major = version[0]
    if major > 15:
        return "UNKNOWN", (
            "version %s is newer than the %s advisory table — check it "
            "against Cisco, this scanner does not guess about releases "
            "it has not seen" % (fmt_version(version), ADVISORY)
        )

    if major < 15:
        detail = (
            "%s: no fix ships on the X%d line — migrate to a fixed "
            "release (%s or later)" % (fmt_version(version), major,
                                        FIXED_LABEL)
        )
    elif version < FIXED_VERSION:
        detail = (
            "%s is below the fixed release %s; upgrade"
            % (fmt_version(version), FIXED_LABEL)
        )
        if version == (15, 5, 3):
            detail += (
                " — X15.5.3 is the fix for the MRA information-disclosure "
                "flaw CVE-2026-76435, not for this one; do not mistake "
                "one patch for the other"
            )
    else:
        return "FIXED", (
            "%s is at or above the fixed release %s"
            % (fmt_version(version), FIXED_LABEL)
        )

    if not clustered:
        return "NOT_EXPOSED", (
            detail + "; this box is declared standalone, and this flaw "
            "needs a cluster, so it is not exposed to %s — but below "
            "%s it is still exposed to the October 2026 hardening set "
            "(CVE-2026-76490 through CVE-2026-76497, up to 8.6), so "
            "patch anyway" % (CVE_MAIN, FIXED_LABEL)
        )
    return "VULNERABLE", detail + (
        "; this flaw needs clustering — if the box is actually "
        "standalone, pass --standalone and it grades NOT_EXPOSED"
    )


def extract_version(text):
    """Pull a version tuple out of free text.

    Prefers a token on a line mentioning version/software/Expressway
    (the login page footer, a Status > System dump, xstatus output),
    and falls back to the first token in the text. Returns
    (version tuple, the token as written) or (None, None).
    """
    if not text:
        return None, None
    candidates = []
    for lineno, line in enumerate(text.splitlines()):
        for match in VERSION_TOKEN.finditer(line):
            # Skip things that are clearly not Expressway releases:
            # years, bare large numbers, and IP fragments. A token
            # with a major above 99 cannot be a release line.
            major = int(match.group(1))
            if major > 99:
                continue
            score = 0
            lowered = line.lower()
            if "version" in lowered or "software" in lowered:
                score += 2
            if "expressway" in lowered:
                score += 1
            candidates.append((score, lineno, match))
    if not candidates:
        return None, None
    # Highest score first, then earliest in the file.
    candidates.sort(key=lambda item: (-item[0], item[1]))
    match = candidates[0][2]
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch), match.group(0)


def _unverified_context():
    """Expressway ships self-signed certificates by default; the
    probe only reads the public login page, so verification is
    skipped the way a browser in a lab does it. Never send
    credentials over this channel — this tool never sends any."""
    return ssl._create_unverified_context()


def fetch(url, timeout=10):
    """Plain HTTPS GET. Returns (status, headers, text).

    Status None means the connection itself failed; the detail string
    says why. HTTPS uses an unverified context (see above).
    """
    headers = {"User-Agent": "expressway-scanner/1.0 (detection-only triage)"}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=_unverified_context()
        ) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body, None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, dict(exc.headers or {}), body, None
    except Exception as exc:  # connection refused, DNS, timeout, TLS
        return None, {}, "", str(exc)


def is_expressway_page(body, headers):
    """True when the page looks like a Cisco Expressway web UI."""
    if not body:
        return False
    lowered = body.lower()
    if "expressway" in lowered:
        return True
    server = (headers or {}).get("Server", "")
    return "expressway" in server.lower()


def check_cluster_ports(host, ports=CLUSTER_PORTS, timeout=3):
    """Bare TCP connects to the cluster database ports. Sends nothing.

    Returns a list of (port, reachable, detail). Open means the
    Erlang cluster service is reachable from this network position;
    closed means it is filtered or the box is down. This is a connect
    check, not a handshake — no Erlang bytes, no cookie, no RPC.
    """
    results = []
    for port in ports:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            results.append((port, True,
                            "TCP %d reachable from here (the cluster "
                            "database service listens here)" % port))
        except Exception as exc:
            results.append((port, False,
                            "TCP %d not reachable (%s)" % (port, exc)))
    return results


def probe_url(base, clustered=True, cluster_ports=CLUSTER_PORTS):
    """Fingerprint a live Expressway and grade it.

    One plain GET of the login page, plus bare TCP connects to ports
    4371/4372. Never sends the cookie, the handshake, or an RPC call.
    Returns a result dict.
    """
    result = {
        "target": base,
        "is_expressway": False,
        "version": None,
        "version_source": None,
        "cluster_ports": {},
        "verdict": "UNKNOWN",
        "detail": "",
    }

    parsed = urllib.parse.urlparse(base)
    host = parsed.hostname or base
    if not parsed.scheme:
        base = "https://" + base
        parsed = urllib.parse.urlparse(base)
        host = parsed.hostname or base

    url = base.rstrip("/") + "/"
    status, headers, body, error = fetch(url)
    if status is None:
        result["detail"] = "Expressway unreachable at %s (%s)" % (url, error)
        return result

    if not is_expressway_page(body, headers):
        result["verdict"] = "NOT_EXPRESSWAY"
        result["detail"] = (
            "%s answered HTTP %s but nothing on the page says "
            "Expressway — wrong host, or a proxy in front of it"
            % (url, status)
        )
        return result
    result["is_expressway"] = True

    for port, reachable, detail in check_cluster_ports(host, cluster_ports):
        result["cluster_ports"][str(port)] = {
            "reachable": reachable,
            "detail": detail,
        }

    version, token = extract_version(body)
    if version is None:
        result["verdict"] = "UNKNOWN"
        result["detail"] = (
            "this is an Expressway, but the login page discloses no "
            "version — check Status > System on the box, or grade it "
            "with --version"
        )
        return result
    result["version"] = fmt_version(version)
    result["version_source"] = "login page (%s)" % token

    verdict, why = grade(version, clustered=clustered)
    result["verdict"] = verdict
    result["detail"] = why
    ports_open = [port for port, info in result["cluster_ports"].items()
                  if info["reachable"]]
    if verdict == "VULNERABLE" and not ports_open:
        result["detail"] += (
            "; TCP 4371/4372 are not reachable from here, which limits "
            "exposure from this network position — it does not fix the "
            "box, anyone on its cluster network can still reach them"
        )
    if verdict == "VULNERABLE" and ports_open:
        result["detail"] += (
            "; cluster database port(s) %s reachable from here — "
            "restrict 4371/4372 to trusted cluster peers at the "
            "firewall until the upgrade lands" % ", ".join(ports_open)
        )
    return result


def _read_text_capped(path):
    """Read a file as text, capped so a huge log cannot OOM us."""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    try:
        with open(path, "rb") as handle:
            data = handle.read(min(size, MAX_LOG_BYTES))
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def hunt_iocs(paths):
    """Grep log files for the compromise signs F6 published.

    Returns a list of {kind, file, line} hits. No hits is not a clean
    bill — it only means these strings were not in the logs checked.
    """
    hits = []
    for path in paths:
        text = _read_text_capped(path)
        if not text:
            continue
        is_relay = "relay" in path.name.lower()
        for lineno, line in enumerate(text.splitlines(), 1):
            for kind, pattern in IOC_PATTERNS:
                if pattern.search(line):
                    hits.append({
                        "kind": kind,
                        "file": str(path),
                        "line": lineno,
                        "sample": line.strip()[:200],
                    })
                    break  # one hit per line is enough
            else:
                if is_relay and RELAY_IOC.search(line):
                    hits.append({
                        "kind": "LOCK/DENY in relay log (F6)",
                        "file": str(path),
                        "line": lineno,
                        "sample": line.strip()[:200],
                    })
    return hits


def find_logs(root):
    """Collect the files worth reading under a path."""
    if root.is_file():
        return [root]
    logs = []
    for name in ("erlang.log", "erlang.log.1"):
        candidate = root / name
        if candidate.is_file():
            logs.append(candidate)
    # Anything else ending .log under the tree, capped.
    for path in root.rglob("*.log"):
        if path.is_file() and path not in logs:
            logs.append(path)
    # A plain version file, if the operator saved one.
    for name in ("version.txt", "xstatus.txt", "system.txt"):
        candidate = root / name
        if candidate.is_file() and candidate not in logs:
            logs.append(candidate)
    return logs[:50]


def read_local(path, clustered=True):
    """Grade an Expressway on disk: version + IOC hunt.

    `path` is a log file (erlang.log), a version file, or a directory
    of logs (e.g. a copied log bundle). Returns a result dict.
    """
    result = {
        "target": str(path),
        "is_expressway": False,
        "version": None,
        "version_source": None,
        "verdict": "UNKNOWN",
        "detail": "",
        "ioc_hits": [],
    }
    target = Path(path)
    if not target.exists():
        result["detail"] = "path does not exist: %s" % path
        return result

    files = find_logs(target)
    if not files:
        result["detail"] = (
            "no .log or version file found under %s — point --local at "
            "the erlang.log file, a log directory, or a file holding "
            "the version string" % path
        )
        return result

    version = None
    token = None
    version_source = None
    for item in files:
        text = _read_text_capped(item)
        version, token = extract_version(text)
        if version is not None:
            version_source = str(item)
            break
    if version is not None:
        result["is_expressway"] = True
        result["version"] = fmt_version(version)
        result["version_source"] = "%s (%s)" % (version_source, token)

    result["ioc_hits"] = hunt_iocs(files)

    if version is None:
        result["detail"] = (
            "files found but no Expressway version string in them — "
            "save the Status > System page or the xstatus output and "
            "point --local at that file"
        )
    else:
        verdict, why = grade(version, clustered=clustered)
        result["verdict"] = verdict
        result["detail"] = why

    if result["ioc_hits"]:
        result["verdict"] = "VULNERABLE"
        result["detail"] += (
            "; COMPROMISE SIGNS FOUND in the logs checked — treat the "
            "box as breached, not just unpatched, and work the "
            "incident response path (rotate service-account passwords "
            "and GitLab tokens, check for staged Python)"
        )
    return result


def verdict_exit(verdict):
    """Map a verdict to this tool's exit code."""
    if verdict in ("VULNERABLE",):
        return EXIT_VULNERABLE
    if verdict == "UNKNOWN":
        return EXIT_UNKNOWN
    return EXIT_CLEAN


def summarise(results):
    """One-line human summary plus the worst exit code."""
    counts = {}
    for item in results:
        counts[item["verdict"]] = counts.get(item["verdict"], 0) + 1
    worst = EXIT_CLEAN
    for item in results:
        worst = max(worst, verdict_exit(item["verdict"]))
    parts = ["%s: %d" % (key, counts[key]) for key in sorted(counts)]
    return ", ".join(parts), worst


def print_result(result, as_json=False):
    """Render one result for a human, or as JSON."""
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("target: %s" % result["target"])
    if result.get("version"):
        source = result.get("version_source") or "given"
        print("version: %s (from %s)" % (result["version"], source))
    if result.get("cluster_ports"):
        for port in sorted(result["cluster_ports"], key=int):
            info = result["cluster_ports"][port]
            print("cluster port TCP %s: %s — %s" % (
                port,
                "reachable" if info["reachable"] else "not reachable",
                info["detail"],
            ))
    if result.get("ioc_hits") is not None:
        if result["ioc_hits"]:
            print("IOC hits: %d" % len(result["ioc_hits"]))
            for hit in result["ioc_hits"]:
                print("  [%s] %s:%s: %s" % (
                    hit["kind"], hit["file"], hit["line"], hit["sample"]))
        else:
            print("IOC hits: none in the logs checked "
                  "(no hits is not a clean bill)")
    print("verdict: %s" % result["verdict"])
    print(result["detail"])


def fixed_table():
    """The advisory table, for --list."""
    return {
        "cve": CVE_MAIN,
        "cvss": CVSS,
        "cwe": CWE,
        "advisory": ADVISORY,
        "cisa_kev_added": "2026-11-20",
        "cisa_kev_due": KEV_DUE,
        "exploited": "yes — F6 reported the first in-the-wild "
                     "exploitation on 2026-11-19 (two internet-facing "
                     "X15.5.3 Expressway-E nodes, pivot to two internal "
                     "cluster nodes)",
        "fixed": {
            "Expressway X15.5.3 and earlier": "X15.5.20 (or later)",
            "Expressway X14 and earlier": "migrate to a fixed release",
            "TelePresence VCS": "no fix (end of life)",
        },
        "workaround": "none — patching is the only fix; until then, "
                      "block TCP 4371/4372 at the firewall except "
                      "between trusted cluster nodes",
        "probe": "one plain GET of the login page + bare TCP connects "
                 "to ports 4371/4372 (no bytes sent, no Erlang "
                 "handshake, no cookie, no RPC)",
    }


def main(argv=None):
    """Parse args, run one mode, exit 0/1/2/3."""
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Cisco Expressway %s "
        "(unauthenticated root RCE in the cluster database service, "
        "CVSS 9.8). No payloads, no Erlang handshake, no exploit "
        "traffic." % CVE_MAIN
    )
    parser.add_argument("--version", metavar="VERSION",
                        help='grade a version string, e.g. "X15.5.3" '
                        'or "X15.5.20"')
    cluster_group = parser.add_mutually_exclusive_group()
    cluster_group.add_argument("--clustered", action="store_true",
                               help="the box runs in a cluster (the "
                               "default assumption)")
    cluster_group.add_argument("--standalone", action="store_true",
                               help="the box is standalone, so this "
                               "flaw's cluster precondition does not "
                               "hold")
    parser.add_argument("--url", metavar="URL",
                        help="probe a live Expressway, e.g. "
                        "https://expressway.example.com")
    parser.add_argument("--local", metavar="PATH",
                        help="grade an Expressway on disk: erlang.log "
                        "file, version file, or log directory, with an "
                        "IOC hunt through the logs")
    parser.add_argument("--inventory-json", metavar="FILE",
                        help="grade a fleet: JSON list of {\"host\", "
                        "\"version\"} and/or {\"host\", \"url\"} objects "
                        "(each may carry \"clustered\": true/false)")
    parser.add_argument("--list", action="store_true",
                        help="print the fixed-version table and exit")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        table = fixed_table()
        if args.json:
            print(json.dumps(table, indent=2, sort_keys=True))
        else:
            for key, value in table.items():
                print("%s: %s" % (key, value))
        return EXIT_CLEAN

    modes = [args.version, args.url, args.local, args.inventory_json]
    if sum(1 for mode in modes if mode) != 1:
        parser.error(
            "exactly one of --version, --url, --local, "
            "--inventory-json is required"
        )

    clustered = not args.standalone

    if args.version:
        parsed = parse_version(args.version)
        verdict, detail = grade(parsed, clustered=clustered)
        result = {
            "target": args.version,
            "version": args.version,
            "verdict": verdict,
            "detail": detail,
        }
        print_result(result, as_json=args.json)
        return verdict_exit(verdict)

    if args.url:
        result = probe_url(args.url, clustered=clustered)
        print_result(result, as_json=args.json)
        return verdict_exit(result["verdict"])

    if args.local:
        result = read_local(args.local, clustered=clustered)
        print_result(result, as_json=args.json)
        return verdict_exit(result["verdict"])

    # --inventory-json
    try:
        inventory = json.loads(Path(args.inventory_json).read_text())
    except (OSError, ValueError) as exc:
        print("cannot read inventory: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    if not isinstance(inventory, list):
        print("inventory must be a JSON list", file=sys.stderr)
        return EXIT_USAGE

    results = []
    for entry in inventory:
        host = entry.get("host", "?")
        entry_clustered = entry.get("clustered", True)
        if entry.get("version"):
            parsed = parse_version(entry["version"])
            verdict, detail = grade(parsed, clustered=entry_clustered)
            results.append({
                "target": host,
                "version": entry["version"],
                "verdict": verdict,
                "detail": detail,
            })
        elif entry.get("url"):
            result = probe_url(entry["url"], clustered=entry_clustered)
            result["target"] = host
            results.append(result)
        else:
            results.append({
                "target": host,
                "verdict": "UNKNOWN",
                "detail": "entry has neither version nor url",
            })

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        for result in results:
            print_result(result)
            print("---")
        summary, _worst = summarise(results)
        print("summary: %s" % summary)
    _summary, worst = summarise(results)
    return worst


if __name__ == "__main__":
    sys.exit(main())
