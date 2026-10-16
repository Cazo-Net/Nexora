# Nexora

[![CI](https://github.com/Cazo-Net/Nexora/actions/workflows/ci.yml/badge.svg)](https://github.com/Cazo-Net/Nexora/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

```
##    ## ######## ##     ##  #######  ########     ###
###   ## ##        ##   ##  ##     ## ##     ##   ## ##
####  ## ##         ## ##   ##     ## ##     ##  ##   ##
## ## ## ######      ###    ##     ## ########  ##     ##
##  #### ##         ## ##   ##     ## ##   ##   #########
##   ### ##        ##   ##  ##     ## ##    ##  ##     ##
##    ## ######## ##     ##  #######  ##     ## ##     ##
```

**Advanced Internet Intelligence Engine** — key-free OSINT from the command line.
Aggregates **25+ public sources** for domains, IPs, emails, URLs, ASNs, phones,
usernames, and social media identities. No API keys, ever. Every source degrades
gracefully — a partial result is always returned.

Includes **Nexconsole**, a Metasploit-style interactive framework
(`use` / `set` / `run` / workspaces / findings database) and a **social media
OSINT center** with cross-platform identity correlation, graphs, posts, media
leak analysis, and brand impersonation detection.

Works on **Kali Linux / any Linux distro** and **Windows** (Python 3.9+).

## Install

### Kali / Linux

```bash
git clone https://github.com/Cazo-Net/Nexora.git
cd Nexora

# recommended: isolated install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# or with pipx (Kali-friendly, no venv needed)
pipx install .

# Kali's system Python is PEP-668 managed — if pip refuses:
pip install --break-system-packages -e .
```

### Windows (PowerShell)

```powershell
git clone https://github.com/Cazo-Net/Nexora.git
cd Nexora
pip install -e .
```

Verify:

```bash
nexora --version        # Nexora 2.1.0
nexora --help           # shows the banner + subcommands
nexconsole --version    # Nexora Nexconsole 2.1.0
```

No install? Run straight from the folder: `python3 -m nexora <args>` or the
legacy single-file engine `python3 osint.py <domain>`.

## Usage

```bash
nexora example.com                        # subcommand auto-detected
nexora domain stripe                      # company name → domain via Wikidata
nexora domain example.com --profile full  # + deep recon
nexora ip 8.8.8.8                         # RDAP, BGP, reputation, Shodan, ports
nexora email admin@example.com            # MX/SPF/DMARC/DKIM, gravatar, breaches
nexora username torvalds                  # 105-site enumeration + enrichments
nexora asn AS13335                        # ASN prefixes, peers, upstreams
nexora url https://example.com            # redirect chain, TLS, header audit
nexora phone +14155552671                 # offline number parsing, carrier, TZ

# social media OSINT center
nexora social identity octocat            # 30+ platforms + correlation score
nexora social graph octocat               # followers, linked identities, link-outs
nexora social posts octocat               # Reddit / HN / GitHub / Dev.to / Medium
nexora social media handle:johndoe        # link-in-bio crawl + EXIF/GPS leaks
nexora social media https://site/pic.jpg  # EXIF metadata / GPS location check
nexora social brand stripe.com            # official accounts + impersonators

# framework
nexora console                            # interactive Nexconsole (or `nexconsole`)
nexora sources                            # source catalog + cache/config status

# machine-readable output
nexora domain example.com --json -o report.json
```

The startup banner can be turned off with `--no-banner` or
`NEXORA_NO_BANNER=1` (it is automatically suppressed in `--json` mode).

## Nexconsole — Metasploit-style framework

```bash
nexconsole            # or: nexora console
```

```
nexora > show modules
nexora (recon/domain) > use recon/domain
nexora (recon/domain) > set target example.com
nexora (recon/domain) > set profile quick
nexora (recon/domain) > show options
nexora (recon/domain) > run
nexora > show findings
nexora > workspace client-a
nexora > search takeover
nexora > notes add "checked with client"
nexora > export report.json
```

* 14 built-in modules (`recon/*`, `social/*`, `util/*`) — lazy-loaded registry
* **Workspaces** + SQLite findings DB (`~/.nexora/nexora.db`): hosts, services,
  findings, evidence, notes — every `run` auto-ingests its results
* Batch mode for scripting: `nexconsole -c "use recon/ip; set target 1.2.3.4; run"`
  or `nexconsole -x commands.txt`
* `set`/`setg`/`unset`/`show options`/`info`/`back`/`history` — msf muscle
  memory works; unknown commands get `did you mean` suggestions

## Social media OSINT center

| Command | What it does |
|---------|--------------|
| `social identity <handle>` | Checks 30–105 platforms, pulls key-free profile metadata (GitHub, Reddit, Keybase, Steam, Linktree…), detects **avatar reuse & bio similarity**, and scores a 0–100 correlation verdict |
| `social graph <handle>` | Nodes/edges: GitHub followers/following, Reddit communities, Keybase linked identities, link-in-bio destinations |
| `social posts <handle>` | Public timelines — Reddit, Hacker News, GitHub events/gists, Dev.to, Medium RSS, Mastodon + dork suggestions for walled gardens |
| `social media <target>` | Pure-Python **EXIF parser** — GPS coordinates, camera make/model, timestamps from images and page image sets; `handle:` mode crawls link-in-bio pages |
| `social brand <domain>` | Scrapes official accounts from the homepage, then hunts **impersonation accounts** (`brand-support`, `brandofficial`…) across platforms |

Walled gardens (X, Instagram, TikTok, Facebook) are never scraped — you get
ready-made dork queries instead. Everything is key-free.

## Scan profiles

| Profile    | Timeout | Behavior                                            |
|------------|---------|-----------------------------------------------------|
| `quick`    | 75s     | Passive overview — skips ports, threat intel, paths |
| `standard` | 120s    | Balanced full scan (default)                        |
| `full`     | 300s    | Everything + deep recon                             |
| `stealth`  | 90s     | Passive-only — no port scans, no path probing       |

```bash
nexora domain example.com --profile stealth
nexora domain example.com --profile quick --skip threat_intel
```

## Watch mode (monitoring & diffing)

Re-scans on an interval and reports what changed (new subdomains, ports,
CVEs, takeover findings, risk-score moves). State persists in
`~/.nexora/state/` so runs resume across restarts.

```bash
nexora domain example.com --watch 3600 --count 24    # hourly, 24 cycles
nexora domain example.com --watch 300 --state-dir ./state
```

## Deep recon (`--deep` or `--profile full`)

* robots.txt + sitemap analysis
* `.well-known/security.txt` (with expiry check)
* Homepage intel: emails, analytics/tracker detection
* Wayback Machine first/last snapshots
* PDF/document metadata (author/creator/producer)
* GitHub / Google / GitLab / Shodan dork suggestions

## Configuration

Optional `~/.nexora/config.toml` (or `NEXORA_CONFIG=<path>`):

```toml
[defaults]
profile = "stealth"
timeout = 90

[net]
proxy = "http://127.0.0.1:8080"   # or socks5://127.0.0.1:9050
per_host_delay = 0.5              # politeness delay (seconds)

[cache]
enabled = true                    # TTL cache in ~/.nexora/cache

[subdomains]
wordlist = "/usr/share/wordlists/subs.txt"

[takeover]
extra_fingerprints = [
  { service = "MyCorp Status", cnames = ["status.mycorp.example"],
    markers = ["Page not found"], vulnerable = true },
]
```

## Output & exit codes

* Colored terminal report (respects `NO_COLOR`, pipes, and both OSes)
* `--json` → stdout (clean for `jq`); `-o FILE` → report file
* Exit codes: `0` ok · `1` failure/bad input · `2` missing dependencies

## Architecture

```
osint.py           engine: lookup_domain() + dataclasses + legacy CLI,
                   HTTP TTL cache, wordlist-driven DNS brute-force
takeover.py        async subdomain-takeover detection (app.engine.takeover copy)
osint_advanced.py  advanced collectors + risk scoring (app.engine.* copy)
nexora/            the suite:
                     cli, banner, config, cache, net, output, profiles,
                     ip, email, username, url, asn, phone, deep,
                     console   Nexconsole REPL
                     modules   lazy module registry (14 built-ins)
                     store     SQLite workspace/findings DB
                     social/   identity, graph, posts, media, brand
tests/             pytest suite (fully offline, mocked HTTP/DNS)
```

The engine prefers `app.engine.*` (FastAPI), then the local sibling copies,
then the `nexora.*` fallbacks — so it runs identically inside the app,
standalone, or pip-installed on any OS.

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

237 tests, all hermetic — no network access is required (or allowed).

## Legal

For authorized testing and defensive use only. Running scans against targets
you do not own or lack written permission to test may violate law and
provider terms.

---

© Cazo-Net · [github.com/Cazo-Net/Nexora](https://github.com/Cazo-Net/Nexora)
