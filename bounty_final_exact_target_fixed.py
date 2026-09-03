import json
import re
import shutil
import subprocess
import time
import ipaddress
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st

# ============================================================
# Jyotir Bug Bounty Automation Framework
# Authorized security testing only.
#
# Pipeline:
# Scope -> passive recon -> DNS/HTTP -> ports -> crawling/URLs
# -> content discovery -> nuclei/custom checks -> correlation
# -> evidence -> reports
#
# The framework deliberately executes only predefined commands
# with argument arrays; it does not expose arbitrary shell input.
# ============================================================

AUTHOR = "Jyotir"
OUTPUT_DIR = Path("scan_results")
OUTPUT_DIR.mkdir(exist_ok=True)

TOOL_CANDIDATES = [
    "subfinder", "assetfinder", "amass", "dnsx", "httpx", "naabu",
    "nmap", "katana", "gau", "waybackurls", "ffuf", "nuclei", "gf"
]

DEFAULT_TIMEOUTS = {
    "subfinder": 300, "assetfinder": 300, "amass": 600, "dnsx": 300,
    "httpx": 300, "naabu": 600, "nmap": 600, "katana": 600,
    "gau": 600, "waybackurls": 600, "ffuf": 900, "nuclei": 900
}

TOOL_COLORS = {
    "subfinder": "#00d9ff", "assetfinder": "#00d9ff", "amass": "#00d9ff",
    "dnsx": "#54d66a", "httpx": "#ff4d4d", "katana": "#54d66a",
    "gau": "#ffd24d", "waybackurls": "#ffd24d", "ffuf": "#ff9f43",
    "nuclei": "#4d8dff", "naabu": "#b86bff", "nmap": "#b86bff",
    "gf": "#ffd24d", "system": "#54d66a", "error": "#ff6b6b"
}


def write_text(path: Path, content: str = ""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content or "", encoding="utf-8", errors="replace")
    return path


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def validate_target(target: str) -> bool:
    target = target.strip()
    if not target or len(target) > 253:
        return False

    # No shell control characters.
    if any(c in target for c in ["\n", "\r", ";", "|", "&", "`", "$", "(", ")",
                                 "<", ">", "{", "}", "\x00"]):
        return False

    if target.startswith(("http://", "https://")):
        try:
            p = urlparse(target)
            return bool(p.hostname) and not p.username and not p.password
        except Exception:
            return False

    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    domain = r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
    return bool(re.fullmatch(domain, target))


def hostname(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    try:
        return (urlparse(value).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def root_domain(value: str) -> str:
    """Return the registrable/root domain for a target.

    Handles common multi-label public suffixes such as co.uk, so
    transip.co.uk remains transip.co.uk instead of becoming co.uk.
    """
    h = hostname(value)
    if not h:
        return ""
    labels = h.split(".")
    if len(labels) < 2:
        return h
    multi_label_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in",
        "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn",
        "com.sg", "net.sg", "org.sg", "com.my", "net.my", "org.my",
        "co.za", "org.za", "net.za", "com.mx", "com.tr"
    }
    suffix2 = ".".join(labels[-2:])
    if suffix2 in multi_label_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)[:100]


def unique_lines(text: str):
    seen = set()
    out = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def read_lines(path: Path):
    """Read unique, non-empty lines from a text file."""
    if not path.exists():
        return []
    return unique_lines(path.read_text(encoding="utf-8", errors="replace"))


def run_command(command, timeout=300):
    started = time.time()
    try:
        p = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {
            "command": " ".join(map(str, command)),
            "returncode": p.returncode,
            "stdout": p.stdout[-100000:],
            "stderr": p.stderr[-30000:],
            "duration_seconds": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "command": " ".join(map(str, command)),
            "returncode": 124,
            "stdout": stdout[-100000:],
            "stderr": (stderr[-30000:] + "\nCommand timed out."),
            "duration_seconds": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "command": " ".join(map(str, command)),
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
            "duration_seconds": round(time.time() - started, 2),
        }


def terminal_line(tool, message, level="normal"):
    color = TOOL_COLORS.get(tool, TOOL_COLORS["system"])
    if level == "error":
        color = TOOL_COLORS["error"]
    st.markdown(
        f'<div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;'
        f'font-size:13px;line-height:1.5;white-space:pre-wrap;">'
        f'<span style="color:{color};font-weight:700;">[{tool.upper()}]</span> '
        f'<span>{str(message).replace("<","&lt;").replace(">","&gt;")}</span></div>',
        unsafe_allow_html=True,
    )


def save_command_artifacts(directory, name, result):
    write_text(directory / f"{name}_stdout.txt", result.get("stdout", ""))
    write_text(directory / f"{name}_stderr.txt", result.get("stderr", ""))
    return {
        "command": result.get("command"),
        "returncode": result.get("returncode"),
        "duration_seconds": result.get("duration_seconds"),
        "stdout_file": f"{name}_stdout.txt",
        "stderr_file": f"{name}_stderr.txt",
    }


def extract_http_urls(text):
    urls = []
    for line in str(text or "").splitlines():
        line = line.strip()
        for match in re.findall(r"https?://[^\s\"'<>]+", line):
            urls.append(match.rstrip("),]}>"))
    return unique_lines("\n".join(urls))


def run_recon(target, directory, terminal, options):
    """Passive/low-impact asset discovery."""
    root = root_domain(target)
    recon = {}
    subdomains = set()

    if options["subfinder"] and tool_exists("subfinder"):
        terminal_line("subfinder", f"Passive enumeration: {root}")
        r = run_command(["subfinder", "-silent", "-d", root], DEFAULT_TIMEOUTS["subfinder"])
        recon["subfinder"] = save_command_artifacts(directory, "subfinder", r)
        subdomains.update(unique_lines(r["stdout"]))

    if options["assetfinder"] and tool_exists("assetfinder"):
        terminal_line("assetfinder", f"Passive enumeration: {root}")
        r = run_command(["assetfinder", "--subs-only", root], DEFAULT_TIMEOUTS["assetfinder"])
        recon["assetfinder"] = save_command_artifacts(directory, "assetfinder", r)
        subdomains.update(unique_lines(r["stdout"]))

    if options["amass"] and tool_exists("amass"):
        terminal_line("amass", f"Passive enumeration: {root}")
        r = run_command(["amass", "enum", "-passive", "-d", root], DEFAULT_TIMEOUTS["amass"])
        recon["amass"] = save_command_artifacts(directory, "amass", r)
        subdomains.update(unique_lines(r["stdout"]))

    allowed = []
    for s in subdomains:
        h = hostname(s)
        if h == root or h.endswith("." + root):
            allowed.append(h)

    allowed = sorted(set(allowed))
    write_text(directory / "subdomains.txt", "\n".join(allowed) + ("\n" if allowed else ""))
    return recon, allowed


def run_dns_http(subdomains, directory, terminal, options):
    dns_results = {}
    live_hosts = []

    write_text(directory / "subdomains.txt", "\n".join(subdomains) + ("\n" if subdomains else ""))

    if options["dnsx"] and tool_exists("dnsx") and subdomains:
        terminal_line("dnsx", f"Resolving {len(subdomains)} discovered host(s)")
        r = run_command(
            ["dnsx", "-silent", "-l", str(directory / "subdomains.txt")],
            DEFAULT_TIMEOUTS["dnsx"]
        )
        dns_results["dnsx"] = save_command_artifacts(directory, "dnsx", r)
        write_text(directory / "resolved.txt", r["stdout"])
    else:
        write_text(directory / "resolved.txt", "\n".join(subdomains))

    resolved = unique_lines(dns_results.get("dnsx", {}).get("stdout", "\n".join(subdomains)))

    if options["httpx"] and tool_exists("httpx") and resolved:
        terminal_line("httpx", f"Probing {len(resolved)} resolved host(s)")
        r = run_command(
            ["httpx", "-silent", "-status-code", "-title", "-tech-detect",
             "-threads", "100", "-timeout", "10", "-retries", "1",
             "-l", str(directory / "resolved.txt")],
            900
        )
        dns_results["httpx"] = save_command_artifacts(directory, "httpx", r)
        write_text(directory / "httpx.txt", r["stdout"])
        technologies = parse_versioned_technologies(r["stdout"])
        write_text(directory / "technologies.json", json.dumps(technologies, indent=2))
        if technologies:
            terminal_line("httpx", f"Detected {len(technologies)} versioned technolog{'y' if len(technologies) == 1 else 'ies'}")
            for tech in technologies:
                terminal_line("httpx", f"  {tech['technology']} {tech['version']}")
        else:
            terminal_line("httpx", "No versioned technologies detected in httpx -tech-detect output.")
        live_hosts = extract_http_urls(r["stdout"])
    else:
        technologies = []
        write_text(directory / "technologies.json", "[]")
        live_hosts = []
        for h in resolved:
            live_hosts.extend([f"https://{h}", f"http://{h}"])

    write_text(directory / "live_urls.txt", "\n".join(live_hosts) + ("\n" if live_hosts else ""))
    return dns_results, unique_lines("\n".join(live_hosts)), technologies



def parse_versioned_technologies(httpx_text):
    """Extract concrete technology/version pairs from httpx output.

    Supports the normal human-readable httpx -tech-detect output, including:
      https://host [Nginx:1.24.0,PHP:8.2.12]
      https://host [HSTS,Nginx,PHP:5.5.9,Ubuntu]

    Also tolerates JSONL output if httpx is configured with -json.  Only
    entries containing an explicit version are returned because SearchSploit
    correlation is intentionally version-focused.
    """
    technologies = []
    seen = set()

    # Version must contain at least one dot, e.g. 5.5.9, 1.24.0, 6.4.2.
    version_pattern = re.compile(
        r"(?i)(?:^|[ :/_-])v?(\d+(?:\.\d+){1,5})(?=$|[^0-9])"
    )

    def add_item(raw_item):
        item = str(raw_item or "").strip()
        if not item:
            return

        # httpx may render technology strings as:
        #   PHP:5.5.9
        #   PHP/5.5.9
        #   PHP 5.5.9
        #   nginx:1.24.0
        #   WordPress:6.4.2
        m = version_pattern.search(item)
        if not m:
            return

        version = m.group(1)
        name = item[:m.start()].strip(" :/_-\t")
        if not name or not re.search(r"[A-Za-z]", name):
            return

        # Remove display-only prefixes that can occur in JSON/combined output.
        name = re.sub(r"^https?://", "", name, flags=re.I)
        name = re.sub(r"\s+", " ", name).strip()
        if not name:
            return

        key = (name.lower(), version)
        if key in seen:
            return
        seen.add(key)
        technologies.append({
            "technology": name,
            "version": version,
            "raw": item,
        })

    for line in str(httpx_text or "").splitlines():
        line = line.strip()
        if not line:
            continue

        # JSONL support: httpx can emit technology metadata in JSON.  The
        # exact field name can vary between releases, so inspect common keys.
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                candidates = []
                for key in ("tech", "technologies", "technology"):
                    value = obj.get(key)
                    if isinstance(value, list):
                        candidates.extend(value)
                    elif isinstance(value, str):
                        candidates.append(value)
                # Some httpx versions expose technology values under nested
                # metadata-like structures.
                for value in candidates:
                    if isinstance(value, dict):
                        name = value.get("name") or value.get("technology") or ""
                        version = value.get("version") or ""
                        if name and version:
                            add_item(f"{name}:{version}")
                        elif name:
                            add_item(name)
                    else:
                        add_item(value)
                continue

        # Human-readable output.  Parse every bracket group because httpx can
        # place tech-detect data in one or several groups.
        groups = re.findall(r"\[([^\]]+)\]", line)
        for group in groups:
            for raw in group.split(","):
                add_item(raw)

    return technologies


def run_searchsploit(technologies, directory, terminal, options):
    """Search local Exploit-DB entries for detected, versioned technologies.

    This function ONLY searches the local SearchSploit database. It never
    executes, mirrors, or runs an exploit. Every returned match is presented
    as a manual-validation lead for the authorized tester.
    """
    if not technologies:
        write_text(directory / "searchsploit_findings.json", "[]")
        return []

    if not options.get("searchsploit", True):
        terminal_line("searchsploit", "Skipped: SearchSploit integration disabled.")
        write_text(directory / "searchsploit_findings.json", "[]")
        return []

    if not tool_exists("searchsploit"):
        terminal_line(
            "searchsploit",
            "Skipped: searchsploit is not installed. On Kali, install the exploitdb package.",
            "error"
        )
        write_text(directory / "searchsploit_findings.json", "[]")
        return []

    results = []
    seen_queries = set()

    for tech in technologies:
        name = str(tech.get("technology", "")).strip()
        version = str(tech.get("version", "")).strip()
        if not name or not version:
            continue

        query = f"{name} {version}"
        if query.lower() in seen_queries:
            continue
        seen_queries.add(query.lower())

        terminal_line("searchsploit", f"Searching Exploit-DB: {query}")
        r = run_command(
            ["searchsploit", "-j", query],
            60
        )
        safe_query = safe_name(f"{name}_{version}")
        save_command_artifacts(directory, f"searchsploit_{safe_query}", r)

        parsed = []
        try:
            payload = json.loads(r.get("stdout", ""))
            if isinstance(payload, dict):
                parsed = payload.get("RESULTS_EXPLOIT", []) or []
        except json.JSONDecodeError:
            parsed = []

        for item in parsed:
            if not isinstance(item, dict):
                continue
            results.append({
                "technology": name,
                "version": version,
                "query": query,
                "edb_id": item.get("EDB-ID", ""),
                "title": item.get("Title", ""),
                "path": item.get("Path", ""),
                "platform": item.get("Platform", ""),
                "type": item.get("Type", ""),
                "manual_test_required": True,
                "note": "Potential matching Exploit-DB entry. Manually validate applicability and reproduce only within the authorized scope; the framework does not execute exploits.",
            })

    # Deduplicate SearchSploit matches.
    dedup = {}
    for item in results:
        key = "|".join([
            str(item.get("technology", "")),
            str(item.get("version", "")),
            str(item.get("edb_id", "")),
            str(item.get("title", "")),
        ])
        dedup[key] = item

    results = list(dedup.values())
    write_text(directory / "searchsploit_findings.json", json.dumps(results, indent=2))

    terminal_line(
        "searchsploit",
        f"Completed: {len(results)} potential Exploit-DB match(es). Manual validation required."
    )
    return results

def run_ports(targets, directory, terminal, options):
    data = {}

    hosts_file = directory / "port_targets.txt"
    hosts = sorted(set(hostname(x) for x in targets if hostname(x)))
    write_text(hosts_file, "\n".join(hosts) + ("\n" if hosts else ""))

    if options["naabu"] and tool_exists("naabu") and hosts:
        terminal_line("naabu", f"Fast port discovery on {len(hosts)} host(s)")
        r = run_command(
            ["naabu", "-silent", "-list", str(hosts_file), "-top-ports", "100"],
            DEFAULT_TIMEOUTS["naabu"]
        )
        data["naabu"] = save_command_artifacts(directory, "naabu", r)
        write_text(directory / "open_ports.txt", r["stdout"])

    # Nmap is limited to explicit original hosts, not arbitrary discovered IPs.
    if options["nmap"] and tool_exists("nmap"):
        original_hosts = [hostname(x) for x in targets if hostname(x)]
        for i, host in enumerate(sorted(set(original_hosts)), 1):
            name = f"nmap_{i}_{safe_name(host)}"
            terminal_line("nmap", f"Service discovery: {host}")
            xml = directory / f"{name}.xml"
            r = run_command(
                ["nmap", "-sV", "--top-ports", "100", "-T3", "-oX", str(xml), host],
                DEFAULT_TIMEOUTS["nmap"]
            )
            data[name] = save_command_artifacts(directory, name, r)
            if xml.exists():
                # Keep raw XML as evidence; parsing is handled in report generation.
                pass

    return data


def run_url_collection(live_urls, directory, terminal, options):
    results = {}
    urls = set(live_urls)

    live_file = directory / "live_urls.txt"

    if options["katana"] and tool_exists("katana") and live_urls:
        terminal_line("katana", f"Crawling {len(live_urls)} live URL(s)")
        r = run_command(
            ["katana", "-silent", "-list", str(live_file), "-d", "2"],
            DEFAULT_TIMEOUTS["katana"]
        )
        results["katana"] = save_command_artifacts(directory, "katana", r)
        urls.update(extract_http_urls(r["stdout"]))

    if options["gau"] and tool_exists("gau"):
        # gau receives hostnames from the authorized discovered set.
        hosts = sorted(set(hostname(x) for x in live_urls if hostname(x)))
        for i, host in enumerate(hosts, 1):
            terminal_line("gau", f"Collecting known URLs: {host}")
            r = run_command(["gau", "--subs", host], DEFAULT_TIMEOUTS["gau"])
            results[f"gau_{i}"] = save_command_artifacts(directory, f"gau_{i}", r)
            urls.update(extract_http_urls(r["stdout"]))

    if options["waybackurls"] and tool_exists("waybackurls"):
        hosts = sorted(set(hostname(x) for x in live_urls if hostname(x)))
        for i, host in enumerate(hosts, 1):
            terminal_line("waybackurls", f"Collecting archive URLs: {host}")
            r = run_command(["waybackurls", host], DEFAULT_TIMEOUTS["waybackurls"])
            results[f"waybackurls_{i}"] = save_command_artifacts(directory, f"waybackurls_{i}", r)
            urls.update(extract_http_urls(r["stdout"]))

    # Scope enforcement: retain only URLs belonging to authorized roots.
    roots = set(root_domain(x) for x in live_urls)
    scoped = []
    for u in urls:
        h = hostname(u)
        if h and any(h == r or h.endswith("." + r) for r in roots):
            scoped.append(u)

    scoped = sorted(set(scoped))
    write_text(directory / "urls.txt", "\n".join(scoped) + ("\n" if scoped else ""))
    return results, scoped


def run_content_discovery(live_urls, directory, terminal, options):
    if not (options["ffuf"] and tool_exists("ffuf") and live_urls):
        return {}

    wordlist = options["wordlist"]
    if not wordlist or not Path(wordlist).is_file():
        terminal_line("ffuf", "Skipped: configured wordlist was not found.", "error")
        return {}

    results = {}
    # Conservative baseline: small, standard discovery pass per live origin.
    for i, url in enumerate(live_urls[:options["max_fuzz_targets"]], 1):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        name = f"ffuf_{i}_{safe_name(parsed.netloc)}"
        terminal_line("ffuf", f"Content discovery: {base}")
        out = directory / f"{name}.json"
        r = run_command(
            ["ffuf", "-u", base.rstrip("/") + "/FUZZ",
             "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
             "-ac", "-of", "json", "-o", str(out), "-t", "10"],
            DEFAULT_TIMEOUTS["ffuf"]
        )
        results[name] = save_command_artifacts(directory, name, r)
        if out.exists():
            results[name]["result_file"] = out.name
    return results


def parse_nuclei_file(path):
    findings = []
    if not path.exists():
        return findings
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        findings.append({
            "template_id": item.get("template-id") or item.get("templateID"),
            "name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "type": item.get("type", ""),
            "host": item.get("host", ""),
            "matched_at": item.get("matched-at", ""),
            "description": info.get("description", ""),
            "reference": info.get("reference", []),
            "tags": info.get("tags", []),
            "timestamp": item.get("timestamp", ""),
        })
    return findings


def finding_key(f):
    raw = "|".join([
        str(f.get("template_id", "")),
        str(f.get("host", "")),
        str(f.get("matched_at", "")),
        str(f.get("name", "")),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def dedupe_nuclei_targets(urls):
    """
    Reduce discovered URLs to one canonical web origin per hostname.

    Nuclei should assess the web service, not repeatedly scan every
    crawled path. Paths, queries and fragments are therefore removed.
    HTTPS is preferred when both HTTP and HTTPS exist for a host.
    """
    origins = {}

    for value in urls or []:
        value = str(value or "").strip()
        if not value:
            continue

        try:
            parsed = urlparse(value)
        except Exception:
            continue

        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")

        if scheme not in ("http", "https") or not host:
            continue

        try:
            port = parsed.port
        except ValueError:
            continue

        # Preserve explicit non-default ports.
        if port and not (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        ):
            netloc = f"{host}:{port}"
        else:
            netloc = host

        candidate = f"{scheme}://{netloc}"
        key = (host, port)

        existing = origins.get(key)

        # If both schemes are present, prefer HTTPS.
        if existing is None or scheme == "https":
            origins[key] = candidate

    return sorted(origins.values())


def run_nuclei(urls, directory, terminal, options):
    if not (options["nuclei"] and tool_exists("nuclei") and urls):
        return []

    # The crawler can produce many paths on the same host.  Collapse those
    # paths into one canonical origin so Nuclei does not repeatedly scan the
    # same domain.
    targets_list = dedupe_nuclei_targets(urls)

    if not targets_list:
        terminal_line(
            "nuclei",
            "Skipped: no valid HTTP(S) origins were available.",
            "error"
        )
        return []

    targets = directory / "nuclei_targets.txt"
    write_text(targets, "\n".join(targets_list) + "\n")

    severity = ",".join(options["severities"]) or "low,medium,high,critical"
    output = directory / "nuclei.jsonl"

    terminal_line(
        "nuclei",
        f"Starting template scan: {len(targets_list)} unique origin(s), "
        f"severity={severity}"
    )

    command = [
        "nuclei",
        "-silent",
        "-l", str(targets),
        "-severity", severity,
        "-jsonl",
        "-o", str(output),
        "-timeout", "10",
        "-retries", "1"
    ]

    r = run_command(command, DEFAULT_TIMEOUTS["nuclei"])
    save_command_artifacts(directory, "nuclei", r)

    findings = parse_nuclei_file(output)

    dedup = {}
    for f in findings:
        dedup[finding_key(f)] = f

    findings = list(dedup.values())

    write_text(
        directory / "nuclei_findings.json",
        json.dumps(findings, indent=2)
    )

    if r["returncode"] != 0:
        terminal_line(
            "nuclei",
            f"Finished with return code {r['returncode']}: "
            f"{len(findings)} unique finding(s). "
            "Check nuclei_stderr.txt for details.",
            "error"
        )
    else:
        terminal_line(
            "nuclei",
            f"Completed: {len(targets_list)} unique origin(s), "
            f"{len(findings)} unique finding(s)"
        )

    return findings

def severity_rank(s):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        str(s).lower(), 0
    )


def correlate_findings(findings):
    grouped = {}
    for f in findings:
        host = hostname(f.get("matched_at") or f.get("host"))
        item = dict(f)
        item["finding_id"] = finding_key(f)
        item["host_normalized"] = host
        item["priority"] = severity_rank(f.get("severity"))
        grouped.setdefault(host or "unknown", []).append(item)
    return grouped


def build_report(scan):
    meta = scan["meta"]
    findings = scan.get("findings", [])
    grouped = correlate_findings(findings)
    critical = sum(severity_rank(x["severity"]) == 4 for x in findings)
    high = sum(severity_rank(x["severity"]) == 3 for x in findings)
    medium = sum(severity_rank(x["severity"]) == 2 for x in findings)
    low = sum(severity_rank(x["severity"]) == 1 for x in findings)

    rows = []
    for f in sorted(findings, key=lambda x: (-severity_rank(x["severity"]), x["name"])):
        rows.append(
            f"<tr><td>{esc(f.get('severity'))}</td>"
            f"<td>{esc(f.get('name'))}</td>"
            f"<td>{esc(f.get('matched_at') or f.get('host'))}</td>"
            f"<td>{esc(f.get('template_id'))}</td>"
            f"<td>{esc(f.get('description'))}</td></tr>"
        )
    if not rows:
        rows = ['<tr><td colspan="5">No automated findings.</td></tr>']

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Jyotir Bug Bounty Assessment</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:36px;color:#172033;line-height:1.55}}
.cover{{padding:34px;background:#eef4fb;border-radius:16px}}
h1{{color:#0f2747}}h2{{color:#0f2747;border-bottom:1px solid #d8dee9;padding-bottom:7px;margin-top:32px}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:18px 0}}
.card{{border:1px solid #d8dee9;border-radius:12px;padding:14px;background:#fafbfd}}
.num{{font-size:27px;font-weight:bold}}.label{{font-size:12px;color:#667085}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}th,td{{border:1px solid #d8dee9;padding:9px;vertical-align:top;text-align:left}}
th{{background:#f3f6fa}}.small{{font-size:12px;color:#667085}}
</style></head><body>
<div class="cover"><h1>Jyotir Bug Bounty Assessment</h1>
<p><b>Author:</b> {esc(meta['author'])}<br>
<b>Engagement:</b> {esc(meta['engagement'])}<br>
<b>Generated:</b> {esc(meta['generated'])}</p></div>

<div class="grid">
<div class="card"><div class="num">{len(meta['targets'])}</div><div class="label">Scope targets</div></div>
<div class="card"><div class="num">{len(scan.get('subdomains',[]))}</div><div class="label">Subdomains</div></div>
<div class="card"><div class="num">{len(scan.get('live_urls',[]))}</div><div class="label">Live URLs</div></div>
<div class="card"><div class="num">{len(scan.get('urls',[]))}</div><div class="label">Discovered URLs</div></div>
<div class="card"><div class="num">{len(findings)}</div><div class="label">Unique findings</div></div>
</div>

<h2>1. Executive Summary</h2>
<p>The assessment used automated asset discovery, DNS/HTTP discovery, URL collection,
content discovery (when enabled), and template-based vulnerability checks.
Automated findings are leads and require manual validation before reporting.</p>

<h2>2. Scope</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in meta['targets'])}</ul>

<h2>3. Severity Summary</h2>
<p>Critical: <b>{critical}</b> &nbsp; High: <b>{high}</b> &nbsp;
Medium: <b>{medium}</b> &nbsp; Low: <b>{low}</b></p>

<h2>4. Automated Findings</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Endpoint</th><th>Template</th><th>Description</th></tr>
{''.join(rows)}</table>

<h2>5. Attack Surface</h2>
<p><b>Subdomains:</b> {len(scan.get('subdomains',[]))}<br>
<b>Live HTTP endpoints:</b> {len(scan.get('live_urls',[]))}<br>
<b>Discovered URLs:</b> {len(scan.get('urls',[]))}<br>
<b>Open-service records:</b> {len(scan.get('ports',[]))}<br>
<b>Versioned technologies:</b> {len(scan.get('technologies',[]))}<br>
<b>SearchSploit leads:</b> {len(scan.get('searchsploit',[]))}</p>

<h2>6. Methodology</h2>
<ul>
<li>Scope validation and hostname normalization.</li>
<li>Passive subdomain enumeration using installed discovery tools.</li>
<li>DNS resolution and HTTP service discovery.</li>
<li>Limited port/service discovery for explicitly supplied hosts.</li>
<li>Web crawling and passive URL collection where enabled.</li>
<li>Conservative content discovery where a local wordlist is supplied.</li>
<li>Nuclei template-based vulnerability detection.</li>
<li>Versioned technology detection from HTTP probing and local Exploit-DB/SearchSploit correlation.</li>
<li>SearchSploit results are manual-validation leads only; no exploit scripts are executed.</li>
<li>Finding deduplication and severity-based prioritization.</li>
</ul>

<h2>7. Validation Requirements</h2>
<p>Every automated result should be independently reproduced in the authorized
environment. Confirm the affected asset, request/response behavior, impact,
reproduction steps, evidence, severity/CVSS, remediation, and retest status.</p>

<h2>8. Limitations</h2>
<ul>
<li>Tool availability and template coverage affect results.</li>
<li>Automated scanning can produce false positives and false negatives.</li>
<li>Absence of a finding does not prove absence of a vulnerability.</li>
<li>This framework does not perform credential attacks, persistence, or destructive exploitation.</li>
</ul>

<p class="small">Generated by Jyotir Bug Bounty Automation Framework. Authorized testing only.</p>
</body></html>"""
    return html


def esc(value):
    s = str(value or "")
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# ============================================================
# Streamlit UI
# ============================================================

st.set_page_config(
    page_title="Jyotir Bug Bounty Automation",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Jyotir Bug Bounty Automation Framework")
st.caption("Authorized reconnaissance → attack-surface mapping → vulnerability triage → evidence → reporting")

with st.sidebar:
    st.header("Engagement")
    engagement = st.text_input("Engagement name", "Bug Bounty Assessment")
    author = st.text_input("Author", AUTHOR)
    authorization = st.checkbox("I confirm that I have authorization to test these targets.")

    st.divider()
    st.subheader("Recon")
    test_only_given_domain = st.checkbox(
        "Test only given domain(s)",
        False,
        help="When enabled, the framework skips subdomain enumeration and tests only the exact authorized hostnames entered below."
    )
    use_subfinder = st.checkbox("subfinder", True)
    use_assetfinder = st.checkbox("assetfinder", True)
    use_amass = st.checkbox("amass passive", False)
    use_dnsx = st.checkbox("dnsx", True)
    use_httpx = st.checkbox("httpx", True)

    st.subheader("Network")
    use_naabu = st.checkbox("naabu", False)
    use_nmap = st.checkbox("nmap", True)

    st.subheader("Web")
    use_katana = st.checkbox("katana", True)
    use_gau = st.checkbox("gau", True)
    use_wayback = st.checkbox("waybackurls", True)
    use_ffuf = st.checkbox("ffuf content discovery", False)

    wordlist = st.text_input("ffuf wordlist path", "")
    max_fuzz_targets = st.number_input("Maximum origins to fuzz", 1, 100, 10)

    st.subheader("Vulnerability Detection")
    use_nuclei = st.checkbox("nuclei", True)
    severities = st.multiselect(
        "Nuclei severities",
        ["info", "low", "medium", "high", "critical"],
        ["low", "medium", "high", "critical"]
    )
    use_searchsploit = st.checkbox("SearchSploit version lookup", True)

    st.divider()
    st.subheader("Installed tools")
    for tool in TOOL_CANDIDATES:
        if tool_exists(tool):
            st.success(tool)
        else:
            st.caption(f"{tool}: not installed")

targets_input = st.text_area(
    "Authorized targets",
    placeholder="example.com\napp.example.com\nhttps://app.example.com\n192.0.2.10",
    height=150
)

targets = [x.strip() for x in targets_input.splitlines() if x.strip()]
invalid = [x for x in targets if not validate_target(x)]

if invalid:
    st.error("Invalid target(s): " + ", ".join(invalid))

can_scan = authorization and bool(targets) and not invalid

start = st.button("🚀 Start Full Bug Bounty Assessment", type="primary", disabled=not can_scan)

if start:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scan_dir = OUTPUT_DIR / timestamp
    scan_dir.mkdir(parents=True, exist_ok=True)

    options = {
        "subfinder": use_subfinder,
        "test_only_given_domain": test_only_given_domain,
        "assetfinder": use_assetfinder,
        "amass": use_amass,
        "dnsx": use_dnsx,
        "httpx": use_httpx,
        "naabu": use_naabu,
        "nmap": use_nmap,
        "katana": use_katana,
        "gau": use_gau,
        "waybackurls": use_wayback,
        "ffuf": use_ffuf,
        "wordlist": wordlist,
        "max_fuzz_targets": int(max_fuzz_targets),
        "nuclei": use_nuclei,
        "severities": severities,
        "searchsploit": use_searchsploit,
        "targets": targets,
    }

    scan = {
        "meta": {
            "author": author,
            "engagement": engagement,
            "targets": targets,
            "generated": datetime.now(timezone.utc).isoformat(),
            "framework_version": "2.0"
        },
        "subdomains": [],
        "live_urls": [],
        "urls": [],
        "ports": [],
        "technologies": [],
        "findings": [],
        "searchsploit": [],
        "commands": {}
    }

    st.subheader("🖥️ Live Pipeline")
    terminal = st.container()

    with terminal:
        terminal_line("system", "Authorized assessment initialized.")
        terminal_line("system", f"Targets: {len(targets)}")

    # Phase 1: recon
    with terminal:
        if options["test_only_given_domain"]:
            terminal_line(
                "system",
                "Phase 1/6 — exact-target mode (subdomain enumeration disabled)"
            )
            exact_hosts = sorted(set(hostname(x) for x in targets if hostname(x)))
            scan["subdomains"] = exact_hosts
            write_text(
                scan_dir / "subdomains.txt",
                "\n".join(exact_hosts) + ("\n" if exact_hosts else "")
            )
            terminal_line(
                "system",
                f"Exact-target mode: testing only {len(exact_hosts)} given host(s)"
            )
        else:
            terminal_line("system", "Phase 1/6 — asset discovery")
            recon, discovered = run_recon(targets[0], scan_dir, terminal, options)
            scan["commands"].update(recon)
            scan["subdomains"] = sorted(
                set(discovered + [hostname(x) for x in targets if hostname(x)])
            )

            # For multiple roots, run passive enumeration separately.
            for target in targets[1:]:
                if not hostname(target):
                    continue
                root = root_domain(target)
                r2, s2 = run_recon(target, scan_dir, terminal, options)
                scan["commands"].update({f"{root}_{k}": v for k, v in r2.items()})
                scan["subdomains"] = sorted(set(scan["subdomains"] + s2))

    # Phase 2: DNS + HTTP
    with terminal:
        terminal_line("system", "Phase 2/6 — DNS and HTTP discovery")
    dns_data, live, technologies = run_dns_http(scan["subdomains"], scan_dir, terminal, options)
    scan["commands"].update(dns_data)
    scan["live_urls"] = live
    scan["technologies"] = technologies

    # Phase 3: ports
    with terminal:
        terminal_line("system", "Phase 3/6 — service discovery")
    port_data = run_ports(targets, scan_dir, terminal, options)
    scan["commands"].update(port_data)

    # Parse simple naabu output into records.
    port_records = []
    for line in read_lines(scan_dir / "open_ports.txt"):
        if ":" in line:
            host, port = line.rsplit(":", 1)
            port_records.append({"host": host, "port": port})
    scan["ports"] = port_records

    # Phase 4: URLs/crawl
    with terminal:
        terminal_line("system", "Phase 4/6 — web attack-surface mapping")
    url_data, urls = run_url_collection(scan["live_urls"], scan_dir, terminal, options)
    scan["commands"].update(url_data)
    scan["urls"] = urls

    # Phase 5: content discovery
    with terminal:
        terminal_line("system", "Phase 5/6 — content discovery")
    fuzz_data = run_content_discovery(scan["live_urls"], scan_dir, terminal, options)
    scan["commands"].update(fuzz_data)

    # Phase 6: vulnerability detection
    with terminal:
        terminal_line("system", "Phase 6/6 — vulnerability detection and correlation")
    scan["findings"] = run_nuclei(scan["urls"] or scan["live_urls"], scan_dir, terminal, options)

    # Search Exploit-DB/SearchSploit for only technologies where httpx
    # reported a concrete version. Matches are leads for manual validation;
    # no exploit is executed by this framework.
    with terminal:
        terminal_line("system", "Technology → Exploit-DB correlation")
    scan["searchsploit"] = run_searchsploit(scan["technologies"], scan_dir, terminal, options)

    # Persist final state.
    json_file = scan_dir / "scan_report.json"
    json_file.write_text(json.dumps(scan, indent=2), encoding="utf-8")

    html_file = scan_dir / "bug_bounty_report.html"
    html_file.write_text(build_report(scan), encoding="utf-8")

    with terminal:
        terminal_line("system", "Assessment completed successfully.")
        terminal_line("system", f"Subdomains: {len(scan['subdomains'])}")
        terminal_line("system", f"Live URLs: {len(scan['live_urls'])}")
        terminal_line("system", f"Discovered URLs: {len(scan['urls'])}")
        terminal_line("system", f"Findings: {len(scan['findings'])}")

    st.success("Full automated assessment completed. Validate findings manually before reporting.")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Subdomains", len(scan["subdomains"]))
    c2.metric("Live URLs", len(scan["live_urls"]))
    c3.metric("Discovered URLs", len(scan["urls"]))
    c4.metric("Findings", len(scan["findings"]))

    st.subheader("🔎 Findings")
    if scan["findings"]:
        display = []
        for f in scan["findings"]:
            display.append({
                "Severity": f.get("severity"),
                "Finding": f.get("name"),
                "Host": f.get("host"),
                "Matched At": f.get("matched_at"),
                "Template": f.get("template_id"),
            })
        st.dataframe(display, use_container_width=True)
    else:
        st.info("No automated vulnerability findings were returned.")

    st.subheader("🌐 Attack Surface")
    st.write({
        "subdomains": len(scan["subdomains"]),
        "live_urls": len(scan["live_urls"]),
        "discovered_urls": len(scan["urls"]),
        "open_port_records": len(scan["ports"]),
    })

    st.subheader("🧩 Detected Technologies")
    if scan["technologies"]:
        st.dataframe(scan["technologies"], use_container_width=True)
    else:
        st.info("No versioned technologies were detected by httpx.")

    st.subheader("📚 SearchSploit / Exploit-DB Leads")
    if scan["searchsploit"]:
        display_exploits = []
        for e in scan["searchsploit"]:
            display_exploits.append({
                "Technology": e.get("technology"),
                "Version": e.get("version"),
                "EDB-ID": e.get("edb_id"),
                "Exploit": e.get("title"),
                "Type": e.get("type"),
                "Manual Test": "Required",
            })
        st.dataframe(display_exploits, use_container_width=True)
        st.warning("SearchSploit results are potential matches only. Manually validate applicability and test only within the authorized scope. This tool does not execute exploits.")
    else:
        st.info("No SearchSploit matches were returned for the detected versioned technologies.")

    st.subheader("📄 Reports")
    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "⬇️ Download JSON",
            json_file.read_bytes(),
            "scan_report.json",
            "application/json"
        )
    with d2:
        st.download_button(
            "⬇️ Download HTML Report",
            html_file.read_bytes(),
            "bug_bounty_report.html",
            "text/html"
        )

    with st.expander("View complete scan JSON"):
        st.json(scan)

    st.caption(f"Results saved to: {scan_dir}")
