# certwatch

**The problem:** expired TLS certificates take production services down — completely.
Browsers hard-block the site, API clients refuse the handshake, and it almost always
surfaces as a customer-facing outage at the worst possible time. The frustrating part is
that it's one of the most preventable failures in IT: the expiry date was knowable months
in advance. Teams miss it because renewals live in someone's inbox, a spreadsheet, or a
ticket that aged out.

**The fix:** a tiny checker that treats certificate expiry like what it is — a deadline
with a countdown — and shouts before the deadline, not after.

`certwatch` is a single-file, zero-dependency Python script. Give it domains, it tells you
exactly how many days each certificate has left, flags the ones inside your warning
window, and returns exit codes your automation can act on.

## Quick start

```bash
# check domains passed on the command line
python3 certwatch.py example.com github.com

# check a whole fleet from a file (one domain per line)
python3 certwatch.py --file domains.txt --warn-days 45

# machine-readable output for dashboards / pipelines
python3 certwatch.py --file domains.txt --json
```

Example output:

```
OK       github.com                        expires 2027-03-14 (493 days left, issuer: Sectigo Limited)
WARN     internal.example.com              expires 2026-12-02 (22 days left, issuer: Let's Encrypt)
EXPIRED  legacy.example.com                expires 2026-10-30 (-11 days left, issuer: DigiCert Inc)
ERROR    retired.example.com               could not check — gaierror: [Errno -2] Name or service not known
```

## Exit codes (built for CI and cron)

| Code | Meaning |
|------|---------|
| 0 | Every certificate is outside the warning window |
| 1 | Something is `EXPIRED`, or inside the warning window when `--fail-on warn` (the default) |
| 2 | At least one domain could not be checked at all |

Use `--fail-on expired` if you only want the job to go red for certificates that are
already expired, not ones that are merely close.

## Run it on a schedule (GitHub Actions)

Drop this into `.github/workflows/certwatch.yml` and you'll get a failing build — and an
email from GitHub — the week a certificate enters your warning window, instead of a
pager alert the day it expires:

```yaml
name: certwatch
on:
  schedule:
    - cron: "0 13 * * 1"   # Mondays 13:00 UTC
  workflow_dispatch:
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python3 certwatch.py --file domains.txt --warn-days 30
```

## Options

```
positional arguments:
  domains               Domains to check (hostnames only)

options:
  --file FILE           Text file with one domain per line (# comments allowed)
  --port PORT           TLS port (default 443)
  --warn-days N         Warn when a cert expires within N days (default 30)
  --json                Output JSON instead of a table
  --fail-on warn|expired  Exit 1 at this level or worse (default: warn)
  --timeout N           Per-domain timeout in seconds (default 10)
```

## Works behind corporate proxies

If your network only allows egress through an HTTP proxy, certwatch honors the standard
`HTTPS_PROXY` / `ALL_PROXY` environment variables and tunnels through it with HTTP
CONNECT — no code changes, no special flags. Direct connections are used when no proxy
is configured.

## Why not just use monitoring?

You should — if you have it. certwatch is for the gaps monitoring doesn't cover: the
staging box, the vendor portal you don't control, the acquired company's domains nobody
inventoried, the one legacy service that isn't in the CMDB yet. It runs anywhere Python
runs, needs no agent, no account, and no dependencies beyond the standard library.

## License

MIT — see [LICENSE](LICENSE).
