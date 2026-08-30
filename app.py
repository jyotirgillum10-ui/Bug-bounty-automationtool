import json
import re
import shutil
import subprocess
import time
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st


# ============================================================
# Jyotir Bug Bounty Scanner
# Author: Jyotir
#
# Authorized security testing only.
# ============================================================

AUTHOR = "Jyotir"
OUTPUT_DIR = Path("scan_results")
OUTPUT_DIR.mkdir(exist_ok=True)


def write_text_file(path: Path, content: str = ""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content or "", encoding="utf-8")
    return path

def nuclei_output_paths(scan_directory: Path, safe_name: str, index: int):
    base = f"{safe_name}_nuclei_{index}"
    return (scan_directory / f"{base}.jsonl", scan_directory / f"{base}_stdout.txt", scan_directory / f"{base}_stderr.txt")

st.set_page_config(
    page_title="Jyotir Bug Bounty Scanner",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# Utility functions
# ============================================================

def tool_exists(tool_name: str) -> bool:
    """Check whether an external Linux security tool exists."""
    return shutil.which(tool_name) is not None


def validate_target(target: str) -> bool:
    """
    Basic target validation.

    Supports:
      example.com
      sub.example.com
      https://example.com
      http://example.com
      IPv4
      CIDR networks

    This is deliberately conservative.
    """
    target = target.strip()

    if not target:
        return False

    # Prevent shell metacharacters.
    dangerous = [
        "\n",
        "\r",
        ";",
        "|",
        "&",
        "`",
        "$",
        "(",
        ")",
        "<",
        ">",
    ]

    if any(char in target for char in dangerous):
        return False

    if len(target) > 253:
        return False

    # URL target.
    if target.startswith(("http://", "https://")):
        pattern = (
            r"^https?://"
            r"[A-Za-z0-9._:-]+"
            r"(?:/[A-Za-z0-9._~:/?#\[\]@!$'()*+,;=%-]*)?$"
        )
        return bool(re.fullmatch(pattern, target))

    # IP/CIDR.
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # Single IP.
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Domain.
    domain_pattern = (
        r"^(?:"
        r"[A-Za-z0-9]"
        r"[A-Za-z0-9-]{0,61}"
        r"[A-Za-z0-9]"
        r"\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return bool(re.fullmatch(domain_pattern, target))


def run_command(command, timeout=180):
    """
    Execute a predefined command safely.

    Commands are passed as argument arrays instead of shell strings.
    """
    started = time.time()

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "command": " ".join(command),
            "returncode": process.returncode,
            "stdout": process.stdout[-50000:],
            "stderr": process.stderr[-10000:],
            "duration_seconds": round(time.time() - started, 2),
        }

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""

        return {
            "command": " ".join(command),
            "returncode": 124,
            "stdout": stdout[-50000:],
            "stderr": (
                stderr[-10000:]
                + "\nCommand timed out."
            ),
            "duration_seconds": round(time.time() - started, 2),
        }

    except Exception as exc:
        return {
            "command": " ".join(command),
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
            "duration_seconds": round(time.time() - started, 2),
        }


def get_http_urls(target: str):
    """
    Generate HTTP/HTTPS candidates.
    """
    if target.startswith(("http://", "https://")):
        return [target]

    return [
        f"https://{target}",
        f"http://{target}",
    ]


def extract_hostname(value: str) -> str:
    """Return a normalized hostname from a URL or host-like value."""
    value = str(value or "").strip()
    if not value:
        return ""
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/", 1)[0].split(":", 1)[0].strip().lower()
    return value


def collect_observed_subdomains(scan_data):
    """
    Collect unique subdomains observed in authorized target/httpx output.

    The HTML report intentionally stores only the count. Complete raw scan
    data remains available in the downloadable JSON report.
    """
    root_domains = set()
    for target in scan_data.get("meta", {}).get("targets", []):
        host = extract_hostname(target)
        labels = host.split(".")
        if len(labels) >= 2:
            root_domains.add(".".join(labels[-2:]))

    observed = set()
    for target in scan_data.get("meta", {}).get("targets", []):
        host = extract_hostname(target)
        if host and any(host.endswith("." + root) for root in root_domains):
            if host not in root_domains:
                observed.add(host)

    for item in scan_data.get("httpx", []):
        result = item.get("result", {})
        for line in str(result.get("stdout", "")).splitlines():
            host = extract_hostname(line)
            if host and any(host.endswith("." + root) for root in root_domains):
                if host not in root_domains:
                    observed.add(host)

    return sorted(observed)


# ============================================================
# Nmap parser
# ============================================================

def parse_nmap_xml(xml_file: Path):
    """
    Parse Nmap XML and return open services.
    """
    findings = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall("host"):

            address = host.find("address")

            host_ip = ""

            if address is not None:
                host_ip = address.attrib.get("addr", "")

            ports = host.findall(".//port")

            for port in ports:

                state = port.find("state")
                service = port.find("service")

                if state is None:
                    continue

                if state.attrib.get("state") != "open":
                    continue

                port_id = port.attrib.get("portid", "")
                protocol = port.attrib.get("protocol", "")

                service_name = ""
                product = ""
                version = ""

                if service is not None:
                    service_name = service.attrib.get("name", "")
                    product = service.attrib.get("product", "")
                    version = service.attrib.get("version", "")

                findings.append(
                    {
                        "host": host_ip,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    }
                )

    except Exception as exc:
        return [
            {
                "parse_error": str(exc)
            }
        ]

    return findings


# ============================================================
# Nuclei parser
# ============================================================

def parse_nuclei_jsonl(output: str):
    """
    Parse Nuclei JSONL output.
    """
    findings = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        try:
            item = json.loads(line)

            info = item.get("info", {})

            findings.append(
                {
                    "template_id": (
                        item.get("template-id")
                        or item.get("templateID")
                    ),
                    "name": info.get("name", ""),
                    "severity": info.get(
                        "severity",
                        "info",
                    ),
                    "type": item.get("type", ""),
                    "host": item.get("host", ""),
                    "matched_at": item.get(
                        "matched-at",
                        "",
                    ),
                    "description": info.get(
                        "description",
                        "",
                    ),
                    "reference": info.get(
                        "reference",
                        [],
                    ),
                    "tags": info.get(
                        "tags",
                        [],
                    ),
                }
            )

        except json.JSONDecodeError:
            continue

    return findings


# ============================================================
# Professional HTML report
# ============================================================

def escape_html(value):
    value = str(value)

    return (
        value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_html_report(scan_data):
    meta = scan_data["meta"]

    findings_html = ""

    for finding in scan_data.get(
        "nuclei_findings",
        [],
    ):

        findings_html += f"""
        <tr>
            <td>
                {escape_html(finding.get("severity", ""))}
            </td>

            <td>
                {escape_html(finding.get("name", ""))}
            </td>

            <td>
                {escape_html(finding.get("host", ""))}
            </td>

            <td>
                {escape_html(finding.get("matched_at", ""))}
            </td>

            <td>
                {escape_html(
                    finding.get(
                        "description",
                        "",
                    )
                )}
            </td>
        </tr>
        """

    if not findings_html:
        findings_html = """
        <tr>
            <td colspan="5">
                No automated vulnerability findings.
            </td>
        </tr>
        """

    ports_html = ""

    for port in scan_data.get(
        "open_ports",
        [],
    ):

        ports_html += f"""
        <tr>
            <td>
                {escape_html(port.get("host", ""))}
            </td>

            <td>
                {escape_html(port.get("port", ""))}
            </td>

            <td>
                {escape_html(port.get("protocol", ""))}
            </td>

            <td>
                {escape_html(port.get("service", ""))}
            </td>

            <td>
                {escape_html(
                    port.get("product", "")
                )}
                {escape_html(
                    port.get("version", "")
                )}
            </td>
        </tr>
        """

    if not ports_html:
        ports_html = """
        <tr>
            <td colspan="5">
                No open services were parsed.
            </td>
        </tr>
        """

    targets = ", ".join(meta["targets"])
    observed_subdomains = collect_observed_subdomains(scan_data)
    subdomain_count = len(observed_subdomains)

    html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
Penetration Test Report
</title>

<style>

body {{
    font-family:
        Arial,
        Helvetica,
        sans-serif;

    margin: 40px;

    color: #172033;

    line-height: 1.6;
}}

.cover {{
    padding: 50px;

    background: #eef4fb;

    border-radius: 18px;

    margin-bottom: 35px;
}}

h1 {{
    color: #0f2747;
    font-size: 38px;
}}

h2 {{
    color: #0f2747;

    border-bottom:
        1px solid #d8dee9;

    padding-bottom: 8px;

    margin-top: 35px;
}}

table {{
    width: 100%;

    border-collapse:
        collapse;

    margin-top: 15px;
}}

th,
td {{
    border:
        1px solid #d8dee9;

    padding: 10px;

    text-align: left;

    vertical-align: top;
}}

th {{
    background: #f3f6fa;
}}

.badge {{
    display: inline-block;

    padding:
        6px 12px;

    border-radius: 999px;

    background: #dce8f6;

    color: #173b63;

    font-weight: bold;
}}

.small {{
    color: #667085;

    font-size: 13px;
}}

.summary-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    margin: 18px 0 28px;
}}

.summary-card {{
    border: 1px solid #d8dee9;
    border-radius: 14px;
    padding: 18px;
    background: #fafbfd;
}}

.summary-card .number {{
    font-size: 30px;
    font-weight: 700;
    color: #0f2747;
}}

.summary-card .label {{
    color: #667085;
    font-size: 13px;
    margin-top: 3px;
}}

@media print {{
    .summary-grid {{
        break-inside: avoid;
    }}
}}

</style>

</head>

<body>

<div class="cover">

<h1>
Penetration Test Report
</h1>

<p class="badge">
Automated Bug Bounty Assessment
</p>

<p>

<strong>Author:</strong>
{escape_html(meta["author"])}

<br>

<strong>Engagement:</strong>
{escape_html(meta["engagement"])}

<br>

<strong>Generated:</strong>
{escape_html(meta["generated"])}

<br>

<strong>Targets:</strong>
{escape_html(targets)}

</p>

</div>


<div class="summary-grid">
    <div class="summary-card">
        <div class="number">{subdomain_count}</div>
        <div class="label">Subdomains observed</div>
    </div>
    <div class="summary-card">
        <div class="number">{len(scan_data.get("nuclei_findings", []))}</div>
        <div class="label">Automated findings</div>
    </div>
    <div class="summary-card">
        <div class="number">{len(scan_data.get("open_ports", []))}</div>
        <div class="label">Open services</div>
    </div>
</div>

<h2>
1. Executive Summary
</h2>

<p>

This report summarizes automated reconnaissance
and vulnerability-detection results generated by
the Jyotir Bug Bounty Scanner.

Automated findings must be manually validated
before they are considered confirmed security
vulnerabilities.

</p>


<h2>
2. Scope
</h2>

<p>
The following authorized targets were scanned:
</p>

<ul>
"""

    for target in meta["targets"]:
        html += f"""
        <li>
            {escape_html(target)}
        </li>
        """

    html += """
</ul>


<h2>
3. Subdomain Summary
</h2>

<p>
The assessment observed <strong>{subdomain_count}</strong> unique subdomain(s)
within the authorized scope. Individual subdomain names are intentionally
omitted from this professional HTML report to keep it concise and easy to
navigate. The complete underlying scan data remains available in the
downloadable JSON report.
</p>

<h2>
9. Methodology
</h2>

<ul>

<li>
Nmap service discovery using a limited
top-port profile.
</li>

<li>
HTTP service discovery using httpx,
when installed.
</li>

<li>
Nuclei template-based vulnerability
checks, when enabled and installed.
</li>

<li>
No credential attacks, persistence,
destructive exploitation, or arbitrary
shell commands are performed by the
application.
</li>

</ul>


<h2>
4. Automated Findings
</h2>

<table>

<tr>

<th>
Severity
</th>

<th>
Finding
</th>

<th>
Host
</th>

<th>
Matched At
</th>

<th>
Description
</th>

</tr>
"""

    html += findings_html

    html += """
</table>


<h2>
5. Exposed Services
</h2>

<table>

<tr>

<th>
Host
</th>

<th>
Port
</th>

<th>
Protocol
</th>

<th>
Service
</th>

<th>
Product / Version
</th>

</tr>
"""

    html += ports_html

    html += """
</table>


<h2>
6. Risk Assessment
</h2>

<p>

Automated scanner results may contain
false positives and false negatives.

Each finding should be independently
validated within the authorized scope.

Confirmed findings should include:

</p>

<ul>

<li>
Affected asset and endpoint
</li>

<li>
Clear reproduction steps
</li>

<li>
Evidence/screenshots
</li>

<li>
Security impact
</li>

<li>
Severity and CVSS score
</li>

<li>
Recommended remediation
</li>

<li>
Retest status
</li>

</ul>


<h2>
7. Remediation Guidance
</h2>

<p>

Prioritize confirmed high-impact findings.
Remove unnecessary internet-facing services,
keep software patched, harden HTTP configuration,
apply least privilege, and retest after remediation.

</p>


<h2>
8. Limitations
</h2>

<ul>

<li>
This report is based on automated scanner output.
</li>

<li>
Automated results require manual validation.
</li>

<li>
Absence of a finding does not prove absence
of a vulnerability.
</li>

<li>
The scanner does not perform destructive
exploitation.
</li>

</ul>


<hr>

<p class="small">

Generated by Jyotir Bug Bounty Scanner.

Authorized security testing only.

</p>


</body>

</html>
"""

    return html


# ============================================================
# Terminal / tool output
# ============================================================

TOOL_COLORS = {
    "subfinder": "#00d9ff",
    "httpx": "#ff4d4d",
    "nuclei": "#4d8dff",
    "gf": "#ffd24d",
    "nmap": "#b86bff",
    "system": "#54d66a",
    "error": "#ff6b6b",
}


def terminal_line(tool, message, level="normal"):
    """Render one color-coded line in the live scan terminal."""
    color = TOOL_COLORS.get(tool, TOOL_COLORS["system"])
    if level == "error":
        color = TOOL_COLORS["error"]

    st.markdown(
        f'<div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;'
        f'font-size:13px;line-height:1.55;white-space:pre-wrap;">'
        f'<span style="color:{color};font-weight:700;">[{escape_html(tool.upper())}]</span> '
        f'<span style="color:#d9e2f2;">{escape_html(message)}</span></div>',
        unsafe_allow_html=True,
    )


# ============================================================
# UI
# ============================================================

st.title("🛡️ Jyotir Bug Bounty Scanner")

st.caption(
    "Linux reconnaissance + vulnerability triage "
    "+ professional penetration-test reporting"
)


# ============================================================
# Sidebar
# ============================================================

with st.sidebar:

    st.header("Engagement")

    engagement = st.text_input(
        "Engagement name",
        value="Bug Bounty Assessment",
    )

    author = st.text_input(
        "Author",
        value=AUTHOR,
    )

    authorization = st.checkbox(
        "I confirm that I have authorization "
        "to test these targets."
    )

    st.divider()

    st.subheader(
        "Linux Tool Availability"
    )

    tools = [
        "nmap",
        "subfinder",
        "httpx",
        "nuclei",
        "gf",
    ]

    for tool in tools:

        if tool_exists(tool):
            st.success(
                f"{tool}: installed"
            )
        else:
            st.error(
                f"{tool}: not installed"
            )


# ============================================================
# Targets
# ============================================================

targets_input = st.text_area(
    "Authorized targets",
    placeholder=(
        "example.com\n"
        "app.example.com\n"
        "https://app.example.com\n"
        "192.0.2.10"
    ),
    height=150,
)


targets = [
    target.strip()
    for target in targets_input.splitlines()
    if target.strip()
]


invalid_targets = [
    target
    for target in targets
    if not validate_target(target)
]


if invalid_targets:

    st.error(
        "Invalid target(s): "
        + ", ".join(invalid_targets)
    )


# ============================================================
# Scanner options
# ============================================================

st.subheader("Scanner Modules")

st.caption(
    "Terminal colors: 🔴 httpx · 🔵 nuclei · 🟡 gf · 🟣 nmap · 🔷 subfinder"
)

col1, col2, col3 = st.columns(3)


with col1:

    enable_nmap = st.checkbox(
        "Nmap service discovery",
        value=True,
    )


with col2:

    enable_httpx = st.checkbox(
        "HTTP discovery",
        value=True,
    )


with col3:

    enable_nuclei = st.checkbox(
        "Nuclei vulnerability checks",
        value=True,
    )


severities = st.multiselect(
    "Nuclei severities",
    [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ],
    default=[
        "low",
        "medium",
        "high",
        "critical",
    ],
)


# ============================================================
# Scan button
# ============================================================

can_scan = (
    authorization
    and bool(targets)
    and not invalid_targets
)


start_scan = st.button(
    "🚀 Start Authorized Scan",
    type="primary",
    disabled=not can_scan,
)


# ============================================================
# Scan
# ============================================================

if start_scan:

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    scan_directory = (
        OUTPUT_DIR / timestamp
    )

    scan_directory.mkdir(
        parents=True,
        exist_ok=True,
    )


    scan_data = {

        "meta": {

            "author": author,

            "engagement": engagement,

            "targets": targets,

            "generated": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),

        },

        "nmap": [],

        "httpx": [],

        "nuclei_findings": [],

        "open_ports": [],

    }


    # --------------------------------------------------------
    # Progress
    # --------------------------------------------------------

    modules_per_target = 0

    if enable_nmap:
        modules_per_target += 1

    if enable_httpx:
        modules_per_target += 1

    if enable_nuclei:
        modules_per_target += 1


    total_operations = max(
        1,
        len(targets)
        * max(1, modules_per_target),
    )

    completed_operations = 0


    progress = st.progress(0)

    status = st.empty()

    st.subheader("🖥️ Live Tool Terminal")
    terminal = st.container()
    with terminal:
        terminal_line("system", "Authorized scan initialized.")
        terminal_line("system", f"Targets loaded: {len(targets)}")

    # --------------------------------------------------------
    # Target loop
    # --------------------------------------------------------

    for target in targets:

        safe_name = re.sub(
            r"[^A-Za-z0-9_.-]",
            "_",
            target,
        )[:80]


        # ====================================================
        # NMAP
        # ====================================================

        if (
            enable_nmap
            and tool_exists("nmap")
            and not target.startswith(
                (
                    "http://",
                    "https://",
                )
            )
        ):

            status.info(f"Running Nmap against {target}")
            with terminal:
                terminal_line("nmap", f"Scanning {target} (top 100 ports)")

            xml_file = (
                scan_directory
                / f"{safe_name}_nmap.xml"
            )


            command = [
                "nmap",
                "-sV",
                "--top-ports",
                "100",
                "-T3",
                "-oX",
                str(xml_file),
                target,
            ]


            result = run_command(
                command,
                timeout=240,
            )


            scan_data["nmap"].append(
                {
                    "target": target,
                    "result": result,
                }
            )

            with terminal:
                terminal_line(
                    "nmap",
                    f"Completed {target} | returncode={result['returncode']} | "
                    f"{result['duration_seconds']}s",
                    "error" if result["returncode"] != 0 else "normal",
                )


            if xml_file.exists():

                parsed_ports = (
                    parse_nmap_xml(
                        xml_file
                    )
                )

                scan_data[
                    "open_ports"
                ].extend(
                    parsed_ports
                )


            completed_operations += 1

            progress.progress(
                min(
                    1.0,
                    completed_operations
                    / total_operations,
                )
            )


        elif enable_nmap:

            if not tool_exists("nmap"):

                st.warning(
                    "Nmap is not installed. "
                    "Nmap module skipped."
                )

            completed_operations += 1

            progress.progress(
                min(
                    1.0,
                    completed_operations
                    / total_operations,
                )
            )


        # ====================================================
        # HTTPX
        # ====================================================

        urls = get_http_urls(
            target
        )


        if (
            enable_httpx
            and tool_exists("httpx")
        ):

            for url in urls:

                status.info(f"HTTP discovery: {url}")
                with terminal:
                    terminal_line("httpx", f"Probing {url}")


                command = [
                    "httpx",
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-u",
                    url,
                ]


                result = run_command(
                    command,
                    timeout=90,
                )


                scan_data[
                    "httpx"
                ].append(
                    {
                        "target": url,
                        "result": result,
                    }
                )

                with terminal:
                    output_lines = [
                        line.strip()
                        for line in result.get("stdout", "").splitlines()
                        if line.strip()
                    ]
                    if output_lines:
                        for line in output_lines[:12]:
                            terminal_line("httpx", line)
                        if len(output_lines) > 12:
                            terminal_line(
                                "httpx",
                                f"... {len(output_lines) - 12} more output lines saved to JSON",
                            )
                    else:
                        terminal_line(
                            "httpx",
                            f"No HTTP response | returncode={result['returncode']}",
                            "error" if result["returncode"] != 0 else "normal",
                        )


            completed_operations += 1

            progress.progress(
                min(
                    1.0,
                    completed_operations
                    / total_operations,
                )
            )


        elif enable_httpx:

            st.warning(
                "httpx is not installed. "
                "HTTP discovery skipped."
            )

            completed_operations += 1

            progress.progress(
                min(
                    1.0,
                    completed_operations
                    / total_operations,
                )
            )


        # ====================================================
        # NUCLEI
        # ====================================================

        if (
            enable_nuclei
            and tool_exists("nuclei")
        ):

            selected_severity = ",".join(
                severities
            )

            if not selected_severity:

                selected_severity = (
                    "low,medium,high,critical"
                )


            for url in urls:

                status.warning(f"Nuclei vulnerability checks: {url}")
                with terminal:
                    terminal_line("nuclei", f"Scanning {url} | severity={selected_severity}")


                nuclei_index = urls.index(url) + 1
                nuclei_jsonl, nuclei_stdout, nuclei_stderr = nuclei_output_paths(scan_directory, safe_name, nuclei_index)

                command = [
                    "nuclei", "-u", url, "-severity", selected_severity,
                    "-jsonl", "-silent", "-o", str(nuclei_jsonl),
                ]

                result = run_command(command, timeout=300)
                write_text_file(nuclei_stdout, result.get("stdout", ""))
                write_text_file(nuclei_stderr, result.get("stderr", ""))

                file_output = ""
                if nuclei_jsonl.exists():
                    file_output = nuclei_jsonl.read_text(encoding="utf-8", errors="replace")
                if not file_output and result.get("stdout", "").strip():
                    file_output = result["stdout"]
                    write_text_file(nuclei_jsonl, file_output)
                if not nuclei_jsonl.exists():
                    write_text_file(nuclei_jsonl, "")

                findings = parse_nuclei_jsonl(file_output)
                scan_data["nuclei_findings"].extend(findings)

                with terminal:
                    terminal_line("nuclei", f"Completed {url} | {len(findings)} finding(s) | returncode={result['returncode']}", "error" if result["returncode"] != 0 else "normal")
                    terminal_line("nuclei", f"Saved: {nuclei_jsonl.name} ({nuclei_jsonl.stat().st_size} bytes)")
                    if result.get("stderr", "").strip():
                        terminal_line("nuclei", result["stderr"].strip()[-1000:], "error")

            completed_operations += 1

            progress.progress(
                min(
                    1.0,
                    completed_operations
                    / total_operations,
                )
            )


        elif enable_nuclei:

            st.warning(
                "Nuclei is not installed. "
                "Vulnerability checks skipped."
            )

            completed_operations += 1

            progress.progress(
                min(
                    1.0,
                    completed_operations
                    / total_operations,
                )
            )


    # ========================================================
    # Save JSON
    # ========================================================

    json_file = (
        scan_directory
        / "scan_report.json"
    )


    json_file.write_text(
        json.dumps(
            scan_data,
            indent=2,
        ),
        encoding="utf-8",
    )


    # ========================================================
    # Generate HTML report
    # ========================================================

    html_file = (
        scan_directory
        / "penetration_test_report.html"
    )


    html_report = (
        generate_html_report(
            scan_data
        )
    )


    html_file.write_text(
        html_report,
        encoding="utf-8",
    )


    # ========================================================
    # Results
    # ========================================================

    status.success("Scan completed.")

    observed_subdomains = collect_observed_subdomains(scan_data)
    with terminal:
        terminal_line("system", "Scan completed successfully.")
        terminal_line("system", f"Observed subdomains: {len(observed_subdomains)}")
        terminal_line("system", f"Vulnerability findings: {len(scan_data['nuclei_findings'])}")
        terminal_line("system", f"Open services: {len(scan_data['open_ports'])}")

    progress.progress(1.0)


    st.success(
        "Security assessment completed. "
        "Manually validate findings before reporting them."
    )


    # ========================================================
    # Metrics
    # ========================================================

    metric1, metric2, metric3, metric4 = (
        st.columns(4)
    )


    with metric1:

        st.metric(
            "Vulnerability Findings",
            len(
                scan_data[
                    "nuclei_findings"
                ]
            ),
        )


    with metric2:

        st.metric(
            "Open Services",
            len(
                scan_data[
                    "open_ports"
                ]
            ),
        )


    with metric3:

        st.metric(
            "HTTP Targets",
            len(
                scan_data[
                    "httpx"
                ]
            ),
        )

    with metric4:

        st.metric(
            "Subdomains Observed",
            len(collect_observed_subdomains(scan_data)),
        )


    # ========================================================
    # Findings table
    # ========================================================

    st.subheader(
        "🔎 Vulnerability Findings"
    )


    findings = scan_data[
        "nuclei_findings"
    ]


    if findings:

        display_findings = []

        for finding in findings:

            display_findings.append(
                {
                    "Severity": finding.get(
                        "severity",
                        "",
                    ),
                    "Finding": finding.get(
                        "name",
                        "",
                    ),
                    "Host": finding.get(
                        "host",
                        "",
                    ),
                    "Matched At": finding.get(
                        "matched_at",
                        "",
                    ),
                    "Template": finding.get(
                        "template_id",
                        "",
                    ),
                }
            )


        st.dataframe(
            display_findings,
            use_container_width=True,
        )

    else:

        st.info(
            "No automated vulnerability "
            "findings were returned."
        )


    # ========================================================
    # Open ports
    # ========================================================

    st.subheader(
        "🌐 Open Services"
    )


    if scan_data["open_ports"]:

        st.dataframe(
            scan_data["open_ports"],
            use_container_width=True,
        )

    else:

        st.info(
            "No open services were parsed."
        )


    # ========================================================
    # Downloads
    # ========================================================

    st.subheader(
        "📄 Reports"
    )


    download1, download2 = (
        st.columns(2)
    )


    with download1:

        st.download_button(
            label="⬇️ Download Scan JSON",
            data=json_file.read_bytes(),
            file_name="scan_report.json",
            mime="application/json",
        )


    with download2:

        st.download_button(
            label="⬇️ Download Professional PT Report",
            data=html_file.read_bytes(),
            file_name=(
                "penetration_test_report.html"
            ),
            mime="text/html",
        )


    # ========================================================
    # Raw data
    # ========================================================

    with st.expander(
        "View complete scan JSON"
    ):

        st.json(
            scan_data
        )


    st.caption(
        f"Results saved to: "
        f"{scan_directory}"
    )
