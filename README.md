# `cisco-expressway-scanner`

Detection-only triage for `CVE-2026-76466`, the unauthenticated root `RCE` in the cluster database service of clustered `Cisco Expressway-C` and `Expressway-E` that `Cisco` patched on `2026-10-21` in advisory `cisco-sa-vcs-static-cred-hr7EWZ8t` — and that `F6` reported on `2026-11-19` had been exploited in the wild for the first time, against two internet-facing `X15.5.3` boxes that then pivoted into two internal cluster nodes. Grades your `Expressway` version against the fixed release, fingerprints a live install, checks whether the cluster database ports are reachable, and hunts the published compromise signs in your logs. Nothing here opens the `Erlang` distribution service, sends the hard-coded cookie, completes an `Erlang` handshake, or invokes an `RPC` call.

## `What it checks`

* `CVE-2026-76466` — use of hard-coded credentials in the cluster database service. The cluster nodes share a hard-coded `Erlang` cookie, and when `TLS Verify Mode` is set to `Enabled` for clustering, client certificates are not validated. An unauthenticated remote attacker with network access who holds the cookies connects to the database service, invokes `RPC` commands, and runs operating-system commands as `root`. `CVSS 3.1 9.8` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), `CWE-798`. `CISA` added it to `KEV` on `2026-11-20`, due `2026-11-23`. `ZoomEye` counted `39,534` internet-facing `Expressway` assets the day after the advisory.
* The October `2026` batch also shipped a companion flaw — `CVE-2026-76435`, an `MRA` information disclosure (`5.3`, fixed in `X15.5.3`) — and a hardening set, `CVE-2026-76490` through `CVE-2026-76497` (up to `8.6`, fixed in `X15.5.20`). This scanner is about the `9.8` that was already being exploited, but the traps below cover the batch.

Fixed versions, per the `Cisco` advisory (primary source):

| `Build` | `Upgrade to` |
| --- | --- |
| `Expressway X15.5.3` and earlier | `X15.5.20` (or later) |
| `Expressway X14` and earlier | migrate to a fixed release |
| `TelePresence VCS` | no fix (end of life) |

There is no workaround. Patching is the only fix.

## `Usage`

```bash
# grade a version string
python3 expressway_scanner.py --version "X15.5.3"
python3 expressway_scanner.py --version "X15.5.20"
python3 expressway_scanner.py --version "X14.0"

# a box that runs standalone, not in a cluster
python3 expressway_scanner.py --version "X15.5.3" --standalone

# a live Expressway: one plain GET of the login page, plus bare TCP
# connects to ports 4371/4372 (sends nothing, no handshake, no cookie)
python3 expressway_scanner.py --url https://expressway.example.com

# on the box itself (version from the logs + IOC hunt)
python3 expressway_scanner.py --local /tmp/erlang.log
python3 expressway_scanner.py --local /var/log/expressway

# a whole fleet at once
python3 expressway_scanner.py --inventory-json fleet.json

# machine output / the fixed-version table
python3 expressway_scanner.py --version "X15.5.3" --json
python3 expressway_scanner.py --list
```

`--url` `GET`s the login page and reads the version out of it when the page discloses one — then grades it. It also does bare `TCP` connects to ports `4371` and `4372` to say whether the cluster database service is reachable from your network position; the connects send no bytes. `--local` reads the version out of your logs (an `erlang.log`, a `Status > System` dump, an `xstatus` capture) and greps the logs for the compromise signs `F6` published (`wombat@127.0.0.1` `nodeup` lines in `erlang.log`, the `F6` `IOC` addresses `66.179.31.32` and `18.130.47.116`, staged `Python` under `/mnt/harddisk/` and `/dev/shm/pylibs`, `LOCK`/`DENY` in relay logs). `--inventory-json` takes a list of `{"host": "exp-e-1", "version": "X15.5.3"}` or `{"host": "exp-e-1", "url": "https://..."}` objects, each optionally carrying `"clustered": false`.

Exit codes: `0` patched / not exposed / no IOCs, `1` vulnerable or compromise signs found, `2` unknown, `3` usage error.

`Expressway` ships self-signed certificates by default, so the probe skips `TLS` verification the way a browser in a lab does. It never sends credentials over that channel — it never sends any.

## `Traps`

* The `X15.5.3` trap. `X15.5.3` is the fix for the `MRA` information-disclosure flaw `CVE-2026-76435`, not for this one — `F6`'s victims were running `X15.5.3` and were breached anyway. A box on `X15.5.3` that calls itself patched is still vulnerable to `CVE-2026-76466`. This scanner says so out loud.
* The `X14` trap. `X14` has no fix on its own line — the advisory says migrate to a fixed release — and the line stays supported into `2027`, so nothing prompts you to move. There is no patch to wait for. Migrate.
* The clustering trap. This flaw needs a cluster. A standalone `Expressway` is not exposed to this `CVE` — but it is still exposed to the October hardening set (`CVE-2026-76490` through `CVE-2026-76497`, up to `8.6`) while it sits below `X15.5.20`. The scanner assumes clustered unless you pass `--standalone`, because guessing "standalone" would under-report the risk, and a standalone grade still tells you to patch.
* The patch-is-not-enough trap. Patching closes the hole, it does not undo a break-in. `F6`'s intrusion staged `Python` under `/mnt/harddisk`, went after `GitLab` credentials, and probed `SMB`, `SQL Server` and `WinRM` from the `Expressway` itself. Patch, then rotate service-account passwords and `GitLab` tokens, and hunt the `erlang.log` signs. `--local` checks the published signs for you, and no hits in the logs checked is not a clean bill.
* The `4371`/`4372`-quiet trap. A vulnerable version grades `VULNERABLE` even when the cluster ports are not reachable from where you ran the scan. Reachability from your desk is not reachability from the cluster network — anyone on that network can still reach the database service. Until the upgrade lands, block `4371`/`4372` at the firewall except between trusted cluster peers.
* The version-hidden trap. The login page does not always disclose the version. When it does not, this scanner says `UNKNOWN` and tells you to check `Status > System` on the box or grade it with `--version`, it does not guess `FIXED`.

## `Sources`

* `Cisco`, `cisco-sa-vcs-static-cred-hr7EWZ8t` (`2026-10-21`, primary source for the fixed versions, the `9.8` rating and the mechanism)
* `CISA KEV`, `2026-11-20` (added, due `2026-11-23`)
* `F6`, first in-the-wild exploitation report (`2026-11-19`, via `The Hacker News` / `SecurityAffairs` / `SockAnalyst` — two internet-facing `X15.5.3` `Expressway-E` nodes, pivot to two internal nodes, `wombat@127.0.0.1` `nodeup` in `erlang.log`, `IOC` addresses `66.179.31.32` and `18.130.47.116`, staged `Python` under `/mnt/harddisk/`)
* `The Hacker News` / `SecurityAffairs` (`2026-11-20`, corroboration of the exploitation, the `X15.5.20` fix and the `PoC` timeline)
* `GBHackers` / `Undercode News` (`2026-11-12`, the public `PoC` and fleet detector by `Nicolas Krassas` (`dinosn`), validated on `Expressway-C X15.3.2` in a two-node cluster)

Where sources disagree, this scanner follows the vendor advisory and says so. The one live disagreement is a later maintenance release: one secondary write-up mentions `X15.5.22` as a newer build, but `Cisco`'s advisory names `X15.5.20` as the first fixed release, and that is what this tool grades against.

## `Related work`

No `nuclei` template for `CVE-2026-76466` existed as of `2026-11-22`, and no `foxcornlab` scanner covered `Expressway` before this one. A public `PoC` (`dinosn`, `12 Nov`) ships a fleet detector whose `ping` mode authenticates to the `Erlang` service on `TCP 4372` — that proves live exposure, and it is also exploit-adjacent traffic this tool deliberately never sends. This scanner is the defensive counterpart: version grading against the advisory table, a bare-connect exposure check, and the `F6` log hunt, all without touching the vulnerable service.

## `Thanks to`

* `Stefan Aleksic` of `Jane Street` — for reporting the flaw to `Cisco`
* `F6` — for the exploitation report and the indicators that turned a patch into an incident response
* `Cisco PSIRT` — for the advisory and the fixed-release table
* `Nicolas Krassas` (`dinosn`) — for the public `PoC` and detector that showed how the flaw is reached

Educational and defensive use only. This tool detects exposure, it does not exploit anything. If you run `Expressway` in a cluster, patch it to `X15.5.20` — then hunt, because patching alone does not evict an attacker who already staged scripts on your box.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
