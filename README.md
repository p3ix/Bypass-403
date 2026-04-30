# Bypass

403/401 bypass toolkit for bug bounty. One command, all techniques, aggressive by default.

## Install

```bash
cd ~/Bypass
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Basic - runs ALL techniques against the target
bypass https://target.tld/admin

# Self-signed TLS (lab/internal)
bypass https://192.168.0.18:8443/admin -k

# Export results
bypass https://target.tld/admin -k --json results.json --csv results.csv

# Add custom hosts for Host/SNI fuzzing
bypass https://target.tld/admin -k --host internal.target.tld --host localhost

# Rate limit (requests per second)
bypass https://target.tld/admin --rate 10

# Quiet mode (only Top bypasses table + curl)
bypass https://target.tld/admin -k -q

# Follow redirects
bypass https://target.tld/admin -k -L

# Custom methods
bypass https://target.tld/admin -k --method POST --method PUT
```

## What it does

Automatically runs all of these against your target:

- Path mutations (traversal, encoding, null bytes, case tricks, IIS tricks, etc.)
- Header injection (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, etc.)
- Method tampering (verb override, TRACE, non-standard methods)
- Query pollution and encoding tricks
- Protocol switching (HTTP/1.0, HTTP/1.1, HTTP/2)
- Host/SNI fuzzing (X-Forwarded-Host, :authority, custom hosts)
- Smuggling-lite differential probes (CL/TE conflicts)
- Auth challenge probes (Basic, Bearer, NTLM, Negotiate)
- Guided combos (high-yield path + IP headers, method override + encoded paths)

Default bypass IPs injected: `127.0.0.1`, `::1`, `10.0.0.1`, `192.168.0.1`, `0.0.0.0`

## Options

| Flag | Description |
|------|-------------|
| `-k` | Skip TLS verification |
| `-L` | Follow redirects |
| `-q` | Quiet: only show Top bypasses |
| `--timeout N` | Request timeout in seconds (default: 15) |
| `--method M` | HTTP method (repeatable) |
| `--bypass-ip IP` | Extra IP for XFF payloads (repeatable) |
| `--host H` | Extra host for Host/SNI fuzzing (repeatable) |
| `--json FILE` | Export to JSON |
| `--csv FILE` | Export to CSV |
| `--all` | Show all results (not just interesting) |
| `--rate N` | Max requests/second (0 = unlimited) |
| `--top N` | Max entries in Top bypasses table (default: 10) |

## Batch mode

```bash
# Scan multiple targets from a file (one URL per line)
bypass batch targets.txt -k --out-dir results/
```

## Replay findings

```bash
# Re-test interesting findings from a previous scan
bypass replay results.json -k --min-confidence medium
```

## Output

1. **Baseline** - reference status/size of the target
2. **Top bypasses** - ranked table of most promising findings with confidence scores
3. **Curl commands** - copy-paste ready reproduction commands
4. **Full results table** - all attempts (with `--all` or if no interesting findings)

## Development

```bash
. .venv/bin/activate
python -m pytest -q
```
