#!/usr/bin/env python3
"""
Jenkins CVE-2024-23897 Scanner
Detects Jenkins instances and checks for unauthenticated arbitrary file read
via the CLI argument injection vulnerability (args4j @-prefix).

CVE-2024-23897: Jenkins < 2.442 (weekly) | Jenkins LTS < 2.426.3
"""

import argparse
import re
import sys
import concurrent.futures
from urllib.parse import urljoin

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[-] 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ── Detection ────────────────────────────────────────────────────────────────

PROBE_PATHS = [
    "/",
    "/login",
    "/oops",
    "/api/json",
    "/cli",
    "/jenkins/",
    "/jenkins/login",
    "/jenkins/api/json",
]

JENKINS_BODY_INDICATORS = [
    "jenkins",
    "hudson.model",
    "login to jenkins",
    "dashboard [jenkins]",
    "jenkins ver.",
    "hudson.war",
]

VERSION_RE = [
    re.compile(r'"version"\s*:\s*"([\d.]+)"'),
    re.compile(r'Jenkins\s+ver\.\s*([\d.]+)', re.IGNORECASE),
    re.compile(r'<meta\s+name="application-name"\s+content="Jenkins\s+([\d.]+)"', re.IGNORECASE),
]

DEFAULT_TIMEOUT = 10
DEFAULT_UA = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"


# ── Version helpers ──────────────────────────────────────────────────────────

def parse_version(s):
    """Return tuple of ints, e.g. '2.426.2' → (2, 426, 2)."""
    if not s:
        return None
    try:
        return tuple(int(x) for x in s.strip().split("."))
    except ValueError:
        return None


def is_lts(vtuple):
    """LTS releases have 3 components with non-zero patch, e.g. (2, 426, 2)."""
    return vtuple is not None and len(vtuple) >= 3 and vtuple[2] > 0


def vuln_status(vtuple):
    """
    Returns True (vulnerable), False (patched), or None (unknown).
    Fixed: weekly >= 2.442 | LTS >= 2.426.3
    """
    if not vtuple:
        return None
    if is_lts(vtuple):
        return vtuple < (2, 426, 3)
    else:
        return vtuple[:2] < (2, 442)


# ── Core scan functions ──────────────────────────────────────────────────────

def _get(session, url, timeout, stream=False, extra_headers=None):
    headers = {}
    if extra_headers:
        headers.update(extra_headers)
    return session.get(url, timeout=timeout, verify=False,
                       allow_redirects=True, stream=stream, headers=headers)


def _extract_version(resp):
    """Try to pull a Jenkins version string from response headers + body."""
    # Most reliable: X-Jenkins header
    v = resp.headers.get("X-Jenkins", "").strip()
    if v:
        return v
    for pattern in VERSION_RE:
        m = pattern.search(resp.text)
        if m:
            return m.group(1)
    return None


def detect_jenkins(base_url, session, timeout):
    """
    Probe common paths.
    Returns (is_jenkins: bool, version: str|None, found_at: str).
    """
    for path in PROBE_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = _get(session, url, timeout)
        except requests.RequestException:
            continue

        # Header-based detection (definitive)
        if resp.headers.get("X-Jenkins") or resp.headers.get("X-Hudson"):
            version = _extract_version(resp)
            return True, version, url

        # Body-based detection
        body = resp.text.lower()
        if any(ind in body for ind in JENKINS_BODY_INDICATORS):
            version = _extract_version(resp)
            # Supplement with /api/json if version still unknown
            if not version and path not in ("/api/json", "/jenkins/api/json"):
                try:
                    api = urljoin(base_url.rstrip("/") + "/", "api/json")
                    ar = _get(session, api, timeout)
                    version = _extract_version(ar)
                except requests.RequestException:
                    pass
            return True, version, url

        # /api/json structural check
        if path.endswith("/api/json") and resp.status_code == 200:
            try:
                data = resp.json()
                if "_class" in data or "jobs" in data or "views" in data:
                    version = _extract_version(resp)
                    return True, version, url
            except Exception:
                pass

    return False, None, ""


def check_cli_accessible(base_url, session, timeout):
    """
    Check whether the Jenkins CLI HTTP endpoint responds.
    Returns (accessible: bool, http_status: int|None).
    """
    url = urljoin(base_url.rstrip("/") + "/", "cli")
    try:
        resp = _get(session, url, timeout)
        # 200/403 both indicate the endpoint exists
        return resp.status_code in (200, 403, 302), resp.status_code
    except requests.RequestException:
        return False, None


def probe_cli_protocol(base_url, session, timeout):
    """
    Send the Jenkins CLI binary-protocol handshake over HTTP.
    A 200 with octet-stream content-type confirms the CLI channel is open
    and the server is processing the binary protocol — strong indicator of
    an exploitable CVE-2024-23897 surface.

    Returns (confirmed: bool|None, message: str)
      True  → CLI protocol accepted (actively exploitable)
      None  → endpoint reachable but inconclusive (e.g. 403)
      False → endpoint refused / not speaking CLI protocol
    """
    url = urljoin(base_url.rstrip("/") + "/", "cli")
    cli_headers = {
        "Session": "00000000-0000-0000-0000-000000000001",
        "Side": "download",
        "Content-Type": "application/octet-stream",
    }
    try:
        resp = _get(session, url, timeout, stream=True, extra_headers=cli_headers)
        ct = resp.headers.get("Content-Type", "")
        if resp.status_code == 200 and "octet-stream" in ct:
            return True, "CLI binary channel accepted (protocol handshake succeeded)"
        if resp.status_code == 403:
            return None, f"CLI endpoint requires authentication (HTTP 403)"
        return False, f"CLI endpoint returned HTTP {resp.status_code}"
    except requests.RequestException as e:
        return False, f"Connection error: {e}"


# ── Target scanner ───────────────────────────────────────────────────────────

def scan(url, args):
    """Full scan of one URL. Returns a result dict."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    session = requests.Session()
    session.headers["User-Agent"] = DEFAULT_UA
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    result = {
        "url": url,
        "is_jenkins": False,
        "version": None,
        "found_at": "",
        "cli_accessible": False,
        "cli_status": None,
        "vuln": None,        # True / False / None
        "vuln_source": "",   # how we determined vuln status
    }

    # 1. Detect Jenkins
    is_jenkins, version, found_at = detect_jenkins(url, session, args.timeout)
    if not is_jenkins:
        return result

    result.update(is_jenkins=True, version=version, found_at=found_at)

    # 2. Version-based vulnerability assessment
    vtuple = parse_version(version)
    result["vuln"] = vuln_status(vtuple)
    result["vuln_source"] = "version" if vtuple else "unknown"

    # 3. CLI reachability
    cli_ok, cli_status = check_cli_accessible(url, session, args.timeout)
    result["cli_accessible"] = cli_ok
    result["cli_status"] = cli_status

    # 4. Active CLI protocol probe (opt-in or when CLI is open)
    if args.active and cli_ok:
        confirmed, msg = probe_cli_protocol(url, session, args.timeout)
        result["cli_probe_msg"] = msg
        if confirmed is True:
            result["vuln"] = True
            result["vuln_source"] = "active-probe"
        elif confirmed is None:
            # Auth required — version verdict stands, note it
            result["vuln_source"] = result["vuln_source"] + "+cli-auth-required"
    elif args.active and not cli_ok:
        result["cli_probe_msg"] = "CLI endpoint not reachable, skipping active probe"

    return result


# ── Output formatting ────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def color(text, c):
    return f"{c}{text}{RESET}"


def fmt(result, verbose=False, no_color=False):
    def c(text, code):
        return text if no_color else color(text, code)

    if not result["is_jenkins"]:
        if verbose:
            return c(f"[-] {result['url']}  →  Not Jenkins", RESET)
        return ""

    lines = [c(f"\n[+] {result['url']}", BOLD)]
    lines.append(f"    Version  : {result['version'] or 'Unknown'}")
    lines.append(f"    Found at : {result['found_at']}")

    cli_info = f"HTTP {result['cli_status']}" if result['cli_status'] else "unreachable"
    cli_flag = c("OPEN", GREEN) if result["cli_accessible"] else c("CLOSED/FILTERED", YELLOW)
    lines.append(f"    CLI      : {cli_flag}  ({cli_info})")

    if result.get("cli_probe_msg"):
        lines.append(f"    CLI probe: {result['cli_probe_msg']}")

    vuln = result["vuln"]
    src  = result["vuln_source"]
    if vuln is True:
        tag = c("[VULNERABLE]", RED)
        note = "Arbitrary file read — consider PoC with jenkins-cli.jar"
    elif vuln is False:
        tag = c("[PATCHED]", GREEN)
        note = "Version is >= fixed release"
    else:
        tag = c("[UNKNOWN]", YELLOW)
        note = "No version detected — manual verification required"

    lines.append(f"    CVE-2024-23897: {tag}  ({src})  {note}")
    return "\n".join(lines)


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Jenkins CVE-2024-23897 Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
CVE-2024-23897: Unauthenticated arbitrary file read via Jenkins CLI (@-prefix
argument injection in args4j). Affects Jenkins < 2.442 and LTS < 2.426.3.

Examples:
  python jenkins_scan.py -f urls.txt
  python jenkins_scan.py -f urls.txt --active -t 20
  python jenkins_scan.py -f urls.txt --proxy http://127.0.0.1:8080 -o results.txt
  python jenkins_scan.py -f urls.txt --no-color -v
        """,
    )
    parser.add_argument("-f", "--file",    required=True,        help="File with target URLs (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout",       type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--active",        action="store_true",  help="Send CLI binary protocol probe for active verification")
    parser.add_argument("--proxy",                               help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output",                        help="Write results to file")
    parser.add_argument("-v", "--verbose", action="store_true",  help="Show non-Jenkins hosts too")
    parser.add_argument("--no-color",      action="store_true",  help="Disable ANSI color output")
    args = parser.parse_args()

    # Load targets
    try:
        with open(args.file) as fh:
            targets = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        print(f"[-] File not found: {args.file}")
        sys.exit(1)

    if not targets:
        print("[-] No targets in file.")
        sys.exit(1)

    print(f"{BOLD}Jenkins CVE-2024-23897 Scanner{RESET}" if not args.no_color else "Jenkins CVE-2024-23897 Scanner")
    print(f"Targets: {len(targets)}  |  Threads: {args.threads}  |  Active probe: {'ON' if args.active else 'OFF'}")
    print("-" * 60)

    jenkins_hosts  = []
    vuln_hosts     = []
    output_lines   = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan, url, args): url for url in targets}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                if args.verbose:
                    print(f"[-] {url} — error: {exc}")
                continue

            line = fmt(result, verbose=args.verbose, no_color=args.no_color)
            if line:
                print(line)
                output_lines.append(line)

            if result["is_jenkins"]:
                jenkins_hosts.append(url)
                if result["vuln"] is True:
                    vuln_hosts.append(f"{url}  (v{result['version'] or '?'})")

    # Summary
    sep = "=" * 60
    summary = [
        "",
        sep,
        f"Scan complete",
        f"Jenkins detected : {len(jenkins_hosts)}",
        f"Likely vulnerable: {len(vuln_hosts)}",
    ]
    if vuln_hosts:
        summary.append("\nVulnerable targets:")
        for h in vuln_hosts:
            tag = color("[!]", RED) if not args.no_color else "[!]"
            summary.append(f"  {tag} {h}")

    summary_text = "\n".join(summary)
    print(summary_text)
    output_lines.append(summary_text)

    if args.output:
        # Strip ANSI for file output
        ansi_re = re.compile(r'\x1b\[[0-9;]*m')
        clean = ansi_re.sub("", "\n".join(output_lines))
        with open(args.output, "w") as fh:
            fh.write(clean)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
