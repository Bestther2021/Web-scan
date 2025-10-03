#!/usr/bin/env python3
# enhanced_webscan.py
# Webscan CLI (B Dev)
# Requires: requests, beautifulsoup4, python-whois, rich (optional)
# Usage:
#   python enhanced_webscan.py http://example.com
#   python enhanced_webscan.py Ws http://example.com --json --rich

import sys
import time
import socket
import ssl
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup
except Exception as e:
    print("Missing dependency: requests and beautifulsoup4 are required.")
    print("Install with: pip install requests beautifulsoup4")
    sys.exit(1)

# whois is optional (not always available on all platforms)
try:
    import whois as whois_lib
except Exception:
    whois_lib = None

# rich is optional; if available we'll use it for pretty CLI output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except Exception:
    RICH_AVAILABLE = False
    console = None


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Content-Type-Options",
]


def ensure_url(u: str) -> str:
    if not u:
        return u
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u


def get_title(html: str) -> str:
    try:
        s = BeautifulSoup(html, "html.parser")
        if s.title and s.title.string:
            return s.title.string.strip()
    except Exception:
        pass
    return "-"


def resolve_ips(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except Exception:
        return []


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


def detect_cdn_and_tech(headers: dict):
    server = (headers.get("Server") or "").lower()
    cdn = "Unknown"
    techs = []
    if "cloudflare" in server or "cf-ray" in headers:
        cdn = "Cloudflare"
    elif "akamai" in server:
        cdn = "Akamai"
    elif "fastly" in server:
        cdn = "Fastly"
    if headers.get("X-Powered-By"):
        techs.append(headers.get("X-Powered-By"))
    if headers.get("Server"):
        techs.append(headers.get("Server"))
    return cdn, ", ".join([t for t in techs if t])


def get_tls_info(hostname: str, port: int = 443, timeout: float = 5.0):
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = {}
                issuer = {}
                for item in cert.get("subject", ()):
                    subject.update({k: v for (k, v) in item})
                for item in cert.get("issuer", ()):
                    issuer.update({k: v for (k, v) in item})
                notBefore = cert.get("notBefore")
                notAfter = cert.get("notAfter")
                info["subject"] = subject
                info["issuer"] = issuer
                info["notBefore"] = notBefore
                info["notAfter"] = notAfter
                # compute days left if possible
                try:
                    # cert dates typically like 'Jun  1 00:00:00 2025 GMT'
                    na = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    info["days_left"] = (na - datetime.utcnow()).days
                except Exception:
                    info["days_left"] = None
    except Exception as e:
        info["error"] = str(e)
    return info


def check_robots(base_url: str):
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        r = requests.get(robots_url, timeout=6, headers={"User-Agent": "webscan-cli/1.0"})
        if r.status_code == 200 and r.text.strip():
            lines = r.text.splitlines()
            sample = lines[:40]
            return True, sample
        return False, []
    except Exception:
        return False, []


def whois_lookup(domain: str):
    if not whois_lib:
        return {"error": "whois library not installed"}
    try:
        w = whois_lib.whois(domain)
        # move to serializable structure
        result = {}
        for k, v in w.items():
            try:
                result[k] = v
            except Exception:
                result[k] = str(v)
        return result
    except Exception as e:
        return {"error": str(e)}


def fingerprint_from_content(text: str, headers: dict):
    hints = []
    t = (text or "").lower()
    if "wp-content" in t or "wordpress" in t:
        hints.append("wordpress")
    if "php" in (headers.get("X-Powered-By") or "").lower():
        hints.append("php")
    if "cloudflare" in (headers.get("Server") or "").lower():
        hints.append("cloudflare")
    return sorted(set(hints))


def classify_content(text: str):
    t = (text or "").lower()
    # simple heuristics
    if any(k in t for k in ["school", "student", "teacher", "class", "faculty", "academy"]):
        return "School / Education"
    if any(k in t for k in ["company", "corporation", "about us", "services", "careers"]):
        return "Organization / Company"
    if any(k in t for k in ["home", "blog", "portfolio", "contact me"]):
        return "Personal / Blog"
    return "Unknown / Other"


def scan(url: str) -> dict:
    url = ensure_url(url)
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = 443 if parsed.scheme == "https" else 80

    result = {
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "url": url,
        "host": host,
    }

    # small delay to simulate the "Delay 3" behavior in examples
    time.sleep(0.2)

    try:
        session = requests.Session()
        headers = {"User-Agent": "webscan-cli/1.0"}
        start = time.time()
        resp = session.get(url, timeout=12, allow_redirects=True, headers=headers)
        duration = time.time() - start

        result.update({
            "http_status": resp.status_code,
            "http_reason": resp.reason,
            "response_time_s": round(duration, 3),
            "content_length": resp.headers.get("Content-Length") or len(resp.content),
            "title": get_title(resp.text),
            "server_header": resp.headers.get("Server"),
            "x_powered_by": resp.headers.get("X-Powered-By"),
            "cookies": requests.utils.dict_from_cookiejar(resp.cookies),
            "headers": dict(resp.headers),
            "final_url": resp.url,
            "redirect_chain": [h.url for h in resp.history] + [resp.url] if resp.history else [resp.url],
        })

        # ips and reverse dns
        ips = resolve_ips(host)
        result["ips"] = ips
        result["reverse_dns"] = {ip: reverse_dns(ip) for ip in ips[:4]}

        # cdn & tech
        cdn, tech = detect_cdn_and_tech(resp.headers)
        result["cdn"] = cdn
        result["tech_hints"] = tech

        # tls
        if parsed.scheme == "https":
            tls = get_tls_info(host, 443)
            result["tls"] = tls

        # security headers
        sec_present = {h: (h in resp.headers) for h in SECURITY_HEADERS}
        missing = [h for h, present in sec_present.items() if not present]
        result["security_headers_present"] = sec_present
        result["security_headers_missing"] = missing

        # robots
        has_robots, robots_sample = check_robots(url)
        result["robots_txt_exists"] = has_robots
        result["robots_txt_sample"] = robots_sample

        # fingerprints & classification
        result["fingerprints"] = fingerprint_from_content(resp.text, resp.headers)
        result["classification"] = classify_content(resp.text)

        # whois (best-effort)
        domain_for_whois = host
        if domain_for_whois:
            result["whois"] = whois_lookup(domain_for_whois)
        else:
            result["whois"] = {}

        result["status"] = "success"
    except requests.exceptions.RequestException as e:
        result["status"] = "failed"
        result["error"] = str(e)

    return result


def print_standard(result: dict):
    if result.get("status") != "success":
        print("\nWebscan by B Dev.")
        print("Scan failed")
        print("----------------------------------")
        print(f"URL       : {result.get('url')}")
        print(f"Error     : {result.get('error')}")
        print("----------------------------------")
        return

    print("\nWebscan by B Dev.")
    print("Scan successfully")
    print("----------------------------------")
    print(f"URL        : {result.get('url')}")
    print(f"Web name   : {result.get('title')}")
    st = f"{result.get('http_status')} {result.get('http_reason')}"
    print(f"Web status : {st} ({'online' if 200 <= result.get('http_status', 0) < 400 else 'offline'})")
    print(f"Response   : {result.get('response_time_s')}s")
    print(f"Content len: {result.get('content_length')}")
    print(f"Host       : {result.get('host')}")
    print("IPs        : " + (", ".join(result.get("ips") or []) or "-"))
    if result.get("reverse_dns"):
        for ip, rev in result.get("reverse_dns", {}).items():
            print(f"  PTR {ip} -> {rev}")
    print(f"Server     : {result.get('server_header') or '-'}")
    print(f"X-Powered-By: {result.get('x_powered_by') or '-'}")
    print(f"CDN / Firewall: {result.get('cdn')}")
    print(f"Redirect chain: {' -> '.join(result.get('redirect_chain') or [])}")
    print(f"Security headers missing: {', '.join(result.get('security_headers_missing') or []) or 'None'}")
    print(f"Robots.txt: {'found' if result.get('robots_txt_exists') else 'not found'}")
    print(f"Cookies returned: {len(result.get('cookies') or {})}")
    print(f"Fingerprint hints: {', '.join(result.get('fingerprints') or []) or '-'}")
    print("\nWhois (summary):")
    who = result.get("whois") or {}
    if isinstance(who, dict) and who:
        # print some common fields if present
        print(f"  Domain: {who.get('domain_name') or who.get('domain') or '-'}")
        print(f"  Registrar: {who.get('registrar') or '-'}")
        org = who.get('org') or who.get('organization') or who.get('registrant_name') or '-'
        print(f"  Organization: {org}")
        print(f"  Country: {who.get('country') or '-'}")
    else:
        print("  Whois: Not available or not installed")
    print("\nClassification (content analysis): " + (result.get("classification") or "-"))
    if result.get("tls"):
        tls = result.get("tls")
        if tls.get("error"):
            print("TLS info  : could not fetch -", tls.get("error"))
        else:
            print("TLS Subject : ", tls.get("subject"))
            print("TLS Issuer  : ", tls.get("issuer"))
            print("TLS valid   : from", tls.get("notBefore"), "to", tls.get("notAfter"),
                  f"({tls.get('days_left')} days left)" if tls.get('days_left') is not None else "")
    print("----------------------------------")


def print_rich(result: dict):
    if not RICH_AVAILABLE:
        # fallback
        print_standard(result)
        return

    if result.get("status") != "success":
        console.print(Panel("[bold red]Webscan by B Dev — FAILED[/bold red]"))
        console.print(f"[red]Error:[/red] {result.get('error')}")
        return

    console.print(Panel("[bold green]Webscan by B Dev — SUCCESS[/bold green]"))

    # Summary table
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column("Field", style="cyan", width=18)
    t.add_column("Value", style="white")
    t.add_row("URL", result.get("url") or "-")
    t.add_row("Title", result.get("title") or "-")
    st = f"{result.get('http_status')} {result.get('http_reason')}"
    status_col = f"[green]{st} (online)[/green]" if 200 <= result.get('http_status', 0) < 400 else f"[red]{st} (offline)[/red]"
    t.add_row("Status", status_col)
    t.add_row("Response", f"{result.get('response_time_s')} s")
    t.add_row("Content len", str(result.get("content_length")))
    t.add_row("Host", result.get("host") or "-")
    t.add_row("IPs", ", ".join(result.get("ips") or []) or "-")
    t.add_row("Server", result.get("server_header") or "-")
    t.add_row("CDN/Firewall", result.get("cdn") or "-")
    console.print(t)

    # Security headers
    missing = result.get("security_headers_missing") or []
    if missing:
        console.print(Panel("\n".join(missing), title="Security headers missing", style="yellow"))
    else:
        console.print(Panel("None", title="Security headers missing", style="green"))

    # Robots
    if result.get("robots_txt_exists"):
        sample = "\n".join(result.get("robots_txt_sample") or [])
        console.print(Panel(sample or "-", title="robots.txt (sample)"))
    else:
        console.print(Panel("Not found", title="robots.txt", style="red"))

    # Whois summary
    who = result.get("whois") or {}
    who_text = ""
    if isinstance(who, dict) and who:
        who_text = f"Domain: {who.get('domain_name') or who.get('domain') or '-'}\nRegistrar: {who.get('registrar') or '-'}\nOrganization: {who.get('org') or who.get('organization') or '-'}\nCountry: {who.get('country') or '-'}"
    else:
        who_text = "Whois: Not available or whois lib not installed"
    console.print(Panel(who_text, title="Whois (summary)"))

    # TLS panel
    if result.get("tls"):
        tls = result.get("tls")
        if tls.get("error"):
            console.print(Panel(tls.get("error"), title="TLS", style="red"))
        else:
            tls_text = f"Subject: {tls.get('subject')}\nIssuer: {tls.get('issuer')}\nValid from: {tls.get('notBefore')}\nValid to: {tls.get('notAfter')}\nDays left: {tls.get('days_left')}"
            console.print(Panel(tls_text, title="TLS Info"))

    # classification & fingerprints
    console.print(Panel(f"Classification: {result.get('classification')}\nFingerprints: {', '.join(result.get('fingerprints') or []) or '-'}",
                        title="Analysis"))

    # final small footer
    console.print(f"[dim]Scanned at: {result.get('scanned_at')}[/dim]")


def parse_args(argv):
    """
    Accepts flexible forms:
      - Ws http://example.com
      - http://example.com
      - example.com
    Returns (url, out_json, use_rich)
    """
    args = list(argv)
    out_json = False
    use_rich = False

    if "--json" in args:
        out_json = True
        args.remove("--json")
    if "--rich" in args:
        use_rich = True
        args.remove("--rich")

    if not args:
        return None, out_json, use_rich

    # if first arg is 'Ws' or 'ws', next should be url
    first = args[0]
    if first.lower() == "ws":
        if len(args) >= 2:
            url_candidate = args[1]
        else:
            return None, out_json, use_rich
    else:
        url_candidate = first

    url_candidate = ensure_url(url_candidate)
    return url_candidate, out_json, use_rich


def main():
    # Accept both: sys.argv[1:] as wrapper will pass all args
    url, out_json, use_rich = parse_args(sys.argv[1:])

    if not url:
        print("Usage: ws http://example.com  OR  ws Ws http://example.com  [--json] [--rich]")
        sys.exit(1)

    # Reminder
    print("Note: Use this tool only on domains you own or have permission to scan.\n")

    result = scan(url)

    if out_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    if use_rich and RICH_AVAILABLE:
        print_rich(result)
    else:
        print_standard(result)


if __name__ == "__main__":
    main()
