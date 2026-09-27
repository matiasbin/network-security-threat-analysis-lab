#!/usr/bin/env python3
"""
network_scanner.py - Authorized network exposure analysis using Nmap.

Part of the "Network Security & Threat Analysis Lab".

Workflow:
    authorized target -> host discovery -> TCP service/version enumeration
    -> Nmap XML parsing -> rule-based exposure review + expected-service baseline
    -> host-level assessment -> terminal/text/JSON reports

Python orchestrates Nmap, parses its XML output, applies transparent review
rules, and writes reports. Nmap does the actual scanning.

Terminology used throughout this tool:
    exposure - a reachable service (an open port), as observed by Nmap.
    finding  - an exposure that a review rule says an analyst should look at,
               with the exact reason and a suggested follow-up.

A finding is NOT a confirmed vulnerability, NOT evidence of malicious activity
and NOT proof of compromise. It is a prompt for human review.

Usage:
    python3 network_scanner.py 10.0.2.15
    python3 network_scanner.py 192.168.56.0/24 --ports 1-1024
    python3 network_scanner.py 10.0.2.15 --expected-ports 22,80
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Only these ranges may be scanned: RFC 1918 private space and loopback.
# Everything else (public Internet, carrier-grade NAT, multicast, reserved)
# is refused. Hostnames are not accepted either, because DNS could resolve
# a harmless-looking name to an address outside the lab.
ALLOWED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Largest network accepted in one run: /24 (256 addresses). This limits the
# impact of a typo such as "10.0.0.0/8" instead of "10.0.0.0/24".
SMALLEST_ALLOWED_PREFIX = 24

# Upper bound on how long a single Nmap run may take before we give up.
NMAP_TIMEOUT_SECONDS = 1800

DEFAULT_REPORT_DIR = Path(__file__).resolve().parent / "reports"

# Accepts Nmap-style TCP port lists such as "22", "1-1024" or "22,80,8000-8100".
PORT_SPEC_PATTERN = re.compile(r"\d+(-\d+)?(,\d+(-\d+)?)*")

# Classification levels, lowest to highest. These describe how much analyst
# attention an exposure deserves. They are not severity ratings of a
# vulnerability and they are deliberately not numeric scores.
INFO = "INFO"
REVIEW = "REVIEW"
HIGH_REVIEW = "HIGH REVIEW"
CLASSIFICATION_ORDER = [INFO, REVIEW, HIGH_REVIEW]

# ---------------------------------------------------------------------------
# Review rules
# ---------------------------------------------------------------------------
# Each rule describes one kind of exposure worth an analyst's attention.
#
#   service_names    - Nmap service names (lowercase) that trigger the rule
#   product_keywords - lowercase substrings of the product Nmap detected
#   exclude_ports    - ports where the rule does not apply
#   skip_if_tls      - skip the rule when Nmap saw the service inside TLS
#
# A rule matches an open port if EITHER a service name OR a product keyword
# matches (and no exclusion applies). If several rules match one port, the
# port still produces ONE finding: it takes the highest classification and
# lists every matching reason.

REVIEW_RULES = [
    {
        "id": "plaintext-remote-login",
        "classification": HIGH_REVIEW,
        # Nmap names rlogin/rsh/rexec (ports 513/514/512) "login"/"shell"/"exec".
        "service_names": {"telnet", "login", "shell", "exec"},
        "skip_if_tls": True,
        "reason": (
            "Remote login service that sends credentials and session data in "
            "cleartext (Telnet or BSD r-services). Anyone who can observe the "
            "traffic can read them."
        ),
        "follow_up": (
            "Confirm why this service is running. Replace it with SSH and "
            "disable it if it is not required."
        ),
    },
    {
        "id": "plaintext-file-transfer",
        "classification": HIGH_REVIEW,
        "service_names": {"ftp"},
        "skip_if_tls": True,
        "reason": (
            "FTP without TLS sends usernames, passwords and file contents in "
            "cleartext."
        ),
        "follow_up": (
            "Confirm the service is required, check whether anonymous login is "
            "enabled, and prefer SFTP or FTPS."
        ),
    },
    {
        "id": "remote-desktop",
        "classification": HIGH_REVIEW,
        "service_names": {"vnc", "ms-wbt-server", "x11"},
        "reason": (
            "Graphical remote-access service (VNC, RDP or X11). If reachable by "
            "others it can give interactive control of the host, and VNC/X11 "
            "have a history of weak or disabled authentication settings."
        ),
        "follow_up": (
            "Verify the exposure is intentional, restrict it to trusted "
            "addresses (firewall or VPN), and confirm strong authentication."
        ),
    },
    {
        "id": "remote-admin-ssh",
        "classification": REVIEW,
        "service_names": {"ssh"},
        "reason": (
            "Remote administration service. SSH is encrypted and common, but "
            "every reachable admin interface is a login surface."
        ),
        "follow_up": (
            "Confirm SSH should be reachable on this interface; check that "
            "password and root logins are disabled or restricted and that the "
            "version is maintained."
        ),
    },
    {
        "id": "file-sharing",
        "classification": REVIEW,
        "service_names": {"microsoft-ds", "netbios-ssn", "nfs", "rpcbind", "mountd"},
        "reason": (
            "File-sharing or RPC service that can expose shared files and host "
            "information to anyone who can reach it."
        ),
        "follow_up": (
            "List the shares/exports, check who may access them, and confirm "
            "the service needs to listen on this interface."
        ),
    },
    {
        "id": "database-exposed",
        "classification": REVIEW,
        "service_names": {
            "mysql", "postgresql", "ms-sql-s", "oracle-tns", "redis",
            "mongodb", "mongod", "memcached", "couchdb", "cassandra",
            "elasticsearch",
        },
        # Nmap often reports Elasticsearch as service "http" with this product.
        "product_keywords": {"elasticsearch"},
        "reason": (
            "Database or data-store service. These usually only need to be "
            "reachable from specific application servers, and some data stores "
            "have historically shipped without authentication enabled by default."
        ),
        "follow_up": (
            "Confirm which clients need access, restrict the listening address "
            "or firewall, and verify that authentication is enforced."
        ),
    },
    {
        "id": "dev-web-server",
        "classification": REVIEW,
        # Server banners of common development/testing web servers:
        # Python http.server ("SimpleHTTPServer"/"BaseHTTPServer"), Flask
        # ("Werkzeug"), Django runserver ("WSGIServer"), Ruby ("WEBrick").
        "product_keywords": {
            "simplehttpserver", "basehttpserver", "werkzeug", "wsgiserver", "webrick",
        },
        "reason": (
            "Nmap identified a development/testing web server. These are built "
            "for local development, not exposed use. Python's http.server, for "
            "example, listens on all interfaces by default and serves a "
            "directory listing without authentication."
        ),
        "follow_up": (
            "Confirm the server was started intentionally, check which "
            "directory it is serving, and stop it or bind it to 127.0.0.1 when "
            "it is not needed."
        ),
    },
    {
        "id": "http-nonstandard-port",
        "classification": REVIEW,
        "service_names": {"http", "http-alt"},
        "exclude_ports": {80, 443},
        "reason": (
            "HTTP service on a non-standard port. Such services are often test, "
            "admin or temporary services that are easy to forget."
        ),
        "follow_up": (
            "Identify the application behind this port and confirm it is "
            "expected to be reachable."
        ),
    },
    {
        "id": "unidentified-service",
        "classification": REVIEW,
        # A missing service name is treated the same as Nmap's "unknown".
        "service_names": {"unknown", "tcpwrapped"},
        "reason": (
            "Nmap could not identify this service (unknown, tcpwrapped, or no "
            "service name). An unidentified listener cannot be judged without "
            "further investigation."
        ),
        "follow_up": (
            "On the host, identify the owning process (for example with "
            "'ss -ltnp') and confirm it is expected."
        ),
    },
]

# Expected-service baseline rule. It only runs when the analyst states the
# baseline with --expected-ports; without one the tool does not guess which
# ports "should" be open. It is kept apart from REVIEW_RULES because it
# depends on that stated baseline, not on what Nmap reported about the service.
UNEXPECTED_SERVICE_RULE = {
    "id": "unexpected-service",
    "classification": REVIEW,
    "reason": (
        "Open TCP port is outside the expected-service baseline stated for "
        "this run (--expected-ports). An exposure that was not planned for "
        "may be forgotten or unmanaged."
    ),
    "follow_up": (
        "Confirm whether this service should be reachable. If it is intended, "
        "add the port to the baseline; otherwise stop it or restrict access."
    ),
}

# Used for open ports that match no rule above.
DEFAULT_INFO_REASON = "Open port with no matching review rule."
DEFAULT_INFO_FOLLOW_UP = "Confirm this service is expected on this host."

# Added to a finding when Nmap only guessed the service name from the port
# number rather than confirming it with a probe response.
TABLE_METHOD_NOTE = (
    "Service name comes from Nmap's port-number table, not from a probe "
    "response; the actual service may differ."
)

DISCLAIMER = (
    "Findings are exposures that warrant analyst review under the transparent "
    "rules in network_scanner.py. They are not confirmed vulnerabilities, "
    "evidence of malicious activity, or proof of compromise."
)

# How missing values are shown in the text report (JSON uses null).
NOT_REPORTED = "not reported by Nmap"

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ScannerError(Exception):
    """An expected problem that should be shown to the user as a message."""


class TargetError(ScannerError):
    """The requested target or port list is invalid or not allowed."""


class NmapError(ScannerError):
    """Nmap is missing, could not run, or failed."""


class NmapXmlError(ScannerError):
    """Nmap's XML output could not be read or understood."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Service:
    """One port entry from Nmap's XML. Missing optional fields are None."""

    port: int
    protocol: str
    state: str
    state_reason: str | None
    name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    tunnel: str | None  # "ssl" when Nmap detected the service inside TLS
    detection_method: str | None  # "probed" (confirmed) or "table" (guessed from port)


@dataclass
class Host:
    """One host from Nmap's XML."""

    ip: str
    hostname: str | None
    status: str
    status_reason: str | None
    services: list[Service] = field(default_factory=list)
    # Ports Nmap summarised instead of listing, e.g. {"closed": 999}.
    unlisted_ports: dict[str, int] = field(default_factory=dict)


@dataclass
class NmapRun:
    """The parts of one Nmap XML file this tool uses."""

    command: str | None
    nmap_version: str | None
    hosts: list[Host]


@dataclass
class Finding:
    """An open port together with the analyst-review outcome for it."""

    ip: str
    hostname: str | None
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    classification: str
    matched_rules: list[str]
    reasons: list[str]
    follow_ups: list[str]
    note: str | None = None


@dataclass
class HostAssessment:
    """Host-level REVIEW outcome, derived only from that host's port findings."""

    ip: str
    hostname: str | None
    classification: str
    reason: str
    contributing_findings: list[str]  # e.g. "8000/tcp [REVIEW] dev-web-server, ..."


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def is_allowed_range(target: ipaddress.IPv4Address | ipaddress.IPv4Network) -> bool:
    """Return True if the address/network lies entirely inside ALLOWED_NETWORKS."""
    if isinstance(target, ipaddress.IPv4Network):
        return any(target.subnet_of(allowed) for allowed in ALLOWED_NETWORKS)
    return any(target in allowed for allowed in ALLOWED_NETWORKS)


def validate_target(text: str) -> ipaddress.IPv4Address | ipaddress.IPv4Network:
    """
    Turn user input into a validated IPv4 address or network.

    Raises TargetError for invalid syntax, IPv6, networks larger than /24,
    and anything outside the allowed private/loopback ranges.
    """
    text = text.strip()
    try:
        if "/" in text:
            # strict=True rejects "10.0.2.15/24" instead of silently widening
            # it to the whole 10.0.2.0/24 network.
            target = ipaddress.ip_network(text, strict=True)
        else:
            target = ipaddress.ip_address(text)
    except ValueError as exc:
        if "has host bits set" in str(exc):
            suggestion = ipaddress.ip_network(text, strict=False)
            if suggestion.prefixlen < SMALLEST_ALLOWED_PREFIX:
                raise TargetError(
                    f"{text} is larger than /{SMALLEST_ALLOWED_PREFIX}. "
                    "Scan smaller networks one at a time."
                ) from exc
            raise TargetError(
                f"'{text}' is not a network address. Use a single host "
                f"(e.g. {text.split('/')[0]}) or the network {suggestion}."
            ) from exc
        raise TargetError(
            f"'{text}' is not a valid IPv4 address or CIDR network. "
            "Hostnames are not accepted."
        ) from exc

    if target.version != 4:
        raise TargetError("Only IPv4 targets are supported.")

    if isinstance(target, ipaddress.IPv4Network):
        if target.prefixlen < SMALLEST_ALLOWED_PREFIX:
            raise TargetError(
                f"{target} is larger than /{SMALLEST_ALLOWED_PREFIX}. "
                "Scan smaller networks one at a time."
            )
        if target.num_addresses == 1:  # a /32 is just one host
            target = target.network_address

    if not is_allowed_range(target):
        allowed = ", ".join(str(n) for n in ALLOWED_NETWORKS)
        raise TargetError(
            f"{target} is outside the allowed lab ranges ({allowed}). "
            "Public and other address ranges are refused by design."
        )
    return target


def validate_port_spec(spec: str) -> str:
    """Check a port list like '22,80,8000-8100' and return it unchanged."""
    spec = spec.strip()
    if not PORT_SPEC_PATTERN.fullmatch(spec):
        raise TargetError(
            f"Invalid port list '{spec}'. Use forms like 22, 1-1024 or 22,80,8000-8100."
        )
    for part in spec.split(","):
        bounds = [int(number) for number in part.split("-")]
        if any(not 1 <= number <= 65535 for number in bounds) or bounds != sorted(bounds):
            raise TargetError(f"Invalid port range '{part}'. Ports must be 1-65535, low-high.")
    return spec


def parse_expected_ports(spec: str) -> set[int]:
    """Turn a port list like '80,443' or '8000-8010' into a set of port numbers."""
    ports = set()
    for part in validate_port_spec(spec).split(","):
        bounds = [int(number) for number in part.split("-")]
        ports.update(range(bounds[0], bounds[-1] + 1))
    return ports


# ---------------------------------------------------------------------------
# Running Nmap
# ---------------------------------------------------------------------------


def require_nmap() -> None:
    """Fail early with a clear message if Nmap is not installed."""
    if shutil.which("nmap") is None:
        raise NmapError("Nmap is not installed or not on PATH. Install it with: sudo apt install nmap")


def run_nmap(options: list[str], targets: list[str], xml_path: Path) -> None:
    """
    Run Nmap with XML output written to xml_path.

    The command is passed to subprocess as a list (no shell), so target text
    can never be interpreted as extra shell commands. Targets have already
    been validated as IP addresses/networks before reaching this point.
    """
    if xml_path.exists():
        raise NmapError(f"Refusing to overwrite existing file {xml_path}.")

    command = ["nmap", *options, "-oX", str(xml_path), *targets]
    print(f"[*] Running: {' '.join(command)}")
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise NmapError(
            "Nmap is not installed or not on PATH. Install it with: sudo apt install nmap"
        ) from exc
    except PermissionError as exc:
        raise NmapError("Permission denied when trying to execute Nmap.") from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"Nmap did not finish within {NMAP_TIMEOUT_SECONDS} seconds.") from exc

    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "no error output"
        if any(word in message.lower() for word in ("root", "privilege", "not permitted")):
            message += "\nHint: this may be a permissions problem; the scan options used here are meant to work without root."
        raise NmapError(f"Nmap exited with code {completed.returncode}: {message}")

    # Nmap can print warnings (for example DNS problems) and still succeed.
    if completed.stderr.strip():
        print(f"[!] Nmap warnings:\n{completed.stderr.strip()}")


def discover_hosts(network: ipaddress.IPv4Network, xml_path: Path) -> NmapRun:
    """
    Host discovery with a ping scan (-sn): find live hosts, no port scan.

    Without root, Nmap cannot send ICMP or ARP; it instead attempts TCP
    connections to ports 80 and 443. A host that ignores those can be missed.
    """
    run_nmap(["-sn"], [str(network)], xml_path)
    return parse_nmap_xml_file(xml_path)


def enumerate_services(targets: list[str], ports: str | None, xml_path: Path) -> NmapRun:
    """
    TCP service/version enumeration on already-selected hosts.

    -sT  TCP connect scan: completes the normal handshake, works without root.
    -sV  version detection: sends probes to open ports and matches responses
         against Nmap's service fingerprint database.
    -Pn  skip host discovery: these hosts were either found live in the
         discovery stage or named explicitly by the user.
    """
    options = ["-sT", "-sV", "-Pn"]
    if ports:
        options += ["-p", ports]
    run_nmap(options, targets, xml_path)
    return parse_nmap_xml_file(xml_path)


# ---------------------------------------------------------------------------
# Parsing Nmap XML
# ---------------------------------------------------------------------------


def _attr(element: ET.Element | None, name: str) -> str | None:
    """Return an XML attribute, or None if the element/attribute is missing or empty."""
    if element is None:
        return None
    value = element.get(name)
    return value if value else None


def parse_port(port_el: ET.Element) -> Service | None:
    """Convert one <port> element into a Service. Returns None if it is malformed."""
    port_text = port_el.get("portid", "")
    if not port_text.isdigit():
        return None  # skip entries we cannot interpret rather than guess
    state_el = port_el.find("state")
    service_el = port_el.find("service")
    return Service(
        port=int(port_text),
        protocol=port_el.get("protocol", "tcp"),
        state=_attr(state_el, "state") or "unknown",
        state_reason=_attr(state_el, "reason"),
        name=_attr(service_el, "name"),
        product=_attr(service_el, "product"),
        version=_attr(service_el, "version"),
        extra_info=_attr(service_el, "extrainfo"),
        tunnel=_attr(service_el, "tunnel"),
        detection_method=_attr(service_el, "method"),
    )


def parse_host(host_el: ET.Element) -> Host | None:
    """Convert one <host> element into a Host. Returns None if it has no IPv4 address."""
    address_el = host_el.find("address[@addrtype='ipv4']")
    ip = _attr(address_el, "addr")
    if ip is None:
        return None  # IPv6/MAC-only entries are outside this tool's scope

    status_el = host_el.find("status")
    host = Host(
        ip=ip,
        hostname=_attr(host_el.find("hostnames/hostname"), "name"),
        status=_attr(status_el, "state") or "unknown",
        status_reason=_attr(status_el, "reason"),
    )

    for port_el in host_el.findall("ports/port"):
        service = parse_port(port_el)
        if service is not None:
            host.services.append(service)

    # Nmap groups uninteresting ports, e.g. <extraports state="closed" count="999">.
    for extra_el in host_el.findall("ports/extraports"):
        state = extra_el.get("state")
        count = extra_el.get("count", "")
        if state and count.isdigit():
            host.unlisted_ports[state] = host.unlisted_ports.get(state, 0) + int(count)

    return host


def parse_nmap_xml(xml_text: str) -> NmapRun:
    """
    Parse Nmap XML text into an NmapRun.

    ElementTree is appropriate here because the XML is produced by the local
    Nmap binary, not by an untrusted third party.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapXmlError(f"Nmap XML is malformed or incomplete: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapXmlError(f"Unexpected XML root element <{root.tag}>; expected <nmaprun>.")

    finished_el = root.find("runstats/finished")
    if finished_el is not None and finished_el.get("exit") == "error":
        raise NmapXmlError(f"Nmap reported an error: {finished_el.get('errormsg', 'no message')}")

    hosts = [parse_host(host_el) for host_el in root.findall("host")]
    return NmapRun(
        command=_attr(root, "args"),
        nmap_version=_attr(root, "version"),
        hosts=[host for host in hosts if host is not None],
    )


def parse_nmap_xml_file(xml_path: Path) -> NmapRun:
    """Read and parse an Nmap XML file."""
    try:
        xml_text = xml_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise NmapXmlError(f"Could not read Nmap XML file {xml_path}: {exc}") from exc
    return parse_nmap_xml(xml_text)


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------


def rule_matches(rule: dict, service: Service) -> bool:
    """Return True if a review rule applies to this service."""
    if service.port in rule.get("exclude_ports", ()):
        return False
    if rule.get("skip_if_tls") and service.tunnel == "ssl":
        return False  # traffic is encrypted, so the cleartext concern does not apply

    name = (service.name or "unknown").lower()
    if name in rule.get("service_names", ()):
        return True
    product = (service.product or "").lower()
    return any(keyword in product for keyword in rule.get("product_keywords", ()))


def is_unexpected(service: Service, expected_ports: set[int] | None) -> bool:
    """True if a baseline was stated and this open TCP port is not in it."""
    if expected_ports is None:
        return False  # no baseline stated, so nothing is "unexpected"
    return service.protocol == "tcp" and service.port not in expected_ports


def analyze_host(host: Host, expected_ports: set[int] | None = None) -> list[Finding]:
    """Apply the review rules (and the baseline, if stated) to every open port on one host."""
    findings = []
    for service in host.services:
        # Only open ports are exposures. Closed/filtered ports are counted in
        # the report but produce no finding, and a host being alive is not a
        # finding on its own.
        if service.state != "open":
            continue

        matched = [rule for rule in REVIEW_RULES if rule_matches(rule, service)]
        # The baseline adds its own reason to the same finding, so one port
        # still yields exactly one finding.
        if is_unexpected(service, expected_ports):
            matched.append(UNEXPECTED_SERVICE_RULE)
        if matched:
            classification = max(
                (rule["classification"] for rule in matched), key=CLASSIFICATION_ORDER.index
            )
            rule_ids = [rule["id"] for rule in matched]
            reasons = [rule["reason"] for rule in matched]
            follow_ups = [rule["follow_up"] for rule in matched]
        else:
            classification = INFO
            rule_ids = []
            reasons = [DEFAULT_INFO_REASON]
            follow_ups = [DEFAULT_INFO_FOLLOW_UP]

        findings.append(
            Finding(
                ip=host.ip,
                hostname=host.hostname,
                port=service.port,
                protocol=service.protocol,
                service=service.name,
                product=service.product,
                version=service.version,
                classification=classification,
                matched_rules=rule_ids,
                reasons=reasons,
                follow_ups=follow_ups,
                note=TABLE_METHOD_NOTE if service.detection_method == "table" else None,
            )
        )
    return findings


def analyze(hosts: list[Host], expected_ports: set[int] | None = None) -> list[Finding]:
    """Analyse all hosts; return findings sorted most-attention-first, then by IP and port."""
    findings = [finding for host in hosts for finding in analyze_host(host, expected_ports)]
    findings.sort(
        key=lambda f: (
            -CLASSIFICATION_ORDER.index(f.classification),
            ipaddress.ip_address(f.ip),
            f.port,
        )
    )
    return findings


def assess_hosts(hosts: list[Host], findings: list[Finding]) -> list[HostAssessment]:
    """
    Give a host-level REVIEW to each host with at least one review-worthy finding.

    The host outcome adds no new judgement: it only rolls up the port findings
    that already warrant review (REVIEW or HIGH REVIEW). INFO findings and a
    host merely being up do not make a host warrant review.
    """
    assessments = []
    for host in sorted(hosts, key=lambda h: ipaddress.ip_address(h.ip)):
        causes = [f for f in findings if f.ip == host.ip and f.classification != INFO]
        if not causes:
            continue
        contributing = [
            f"{f.port}/{f.protocol} [{f.classification}] {', '.join(f.matched_rules)}"
            for f in sorted(causes, key=lambda f: f.port)
        ]
        assessments.append(
            HostAssessment(
                ip=host.ip,
                hostname=host.hostname,
                classification=REVIEW,
                reason=(
                    f"{len(causes)} exposed service(s) on this host produced findings "
                    "that warrant review (listed below). This host-level result is a "
                    "summary of those findings and a prompt for analyst review only."
                ),
                contributing_findings=contributing,
            )
        )
    return assessments


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def local_ipv4_addresses() -> set[str]:
    """Return this machine's IPv4 addresses via `ip -j`, or an empty set if unavailable."""
    try:
        output = subprocess.run(
            ["ip", "-j", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout
        return {
            addr["local"]
            for interface in json.loads(output)
            for addr in interface.get("addr_info", [])
            if "local" in addr
        }
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return set()


def build_scope_notes(
    target: ipaddress.IPv4Address | ipaddress.IPv4Network,
    ports: str | None,
    scanned_ips: list[str],
) -> list[str]:
    """Explain what this scan could and could not see, so results are not over-read."""
    notes = [
        "Only TCP was scanned (connect scan, -sT); UDP services are not covered.",
        "Service and version names are Nmap fingerprint matches and can be inaccurate.",
    ]
    if ports is None:
        notes.append("Only Nmap's default top 1000 TCP ports were scanned.")
    else:
        notes.append(f"Only these TCP ports were scanned: {ports}.")

    if isinstance(target, ipaddress.IPv4Network):
        note = "Host discovery used Nmap's ping scan (-sn); hosts that ignore its probes can be missed."
        if os.geteuid() != 0:
            note += " Without root, Nmap only tries TCP connections to ports 80 and 443 for discovery."
        notes.append(note)
    else:
        notes.append(
            "Host discovery was skipped (-Pn) because the target was named explicitly; "
            "a host status reason of 'user-set' means Nmap assumed the host was up."
        )

    local = local_ipv4_addresses()
    if any(ip in local or ipaddress.ip_address(ip).is_loopback for ip in scanned_ips):
        notes.append(
            "The scan included this machine's own address. That traffic stays inside the "
            "local network stack, so results show what is listening, not what other hosts "
            "can reach through firewalls or NAT."
        )
    return notes


def build_report(
    target: ipaddress.IPv4Address | ipaddress.IPv4Network,
    started: datetime,
    finished: datetime,
    runs: list[NmapRun],
    xml_files: list[Path],
    discovered: list[Host] | None,
    scanned: list[Host],
    findings: list[Finding],
    notes: list[str],
    expected_ports: set[int] | None = None,
) -> dict:
    """Collect everything into one dictionary used for both the JSON and text reports."""
    counts = {level: 0 for level in reversed(CLASSIFICATION_ORDER)}
    for finding in findings:
        counts[finding.classification] += 1
    assessments = assess_hosts(scanned, findings)

    return {
        "tool": "network_scanner.py",
        "scan_started": started.isoformat(timespec="seconds"),
        "scan_finished": finished.isoformat(timespec="seconds"),
        "requested_target": str(target),
        "target_type": "network" if isinstance(target, ipaddress.IPv4Network) else "single host",
        "nmap_version": next((run.nmap_version for run in runs if run.nmap_version), None),
        "nmap_commands": [run.command for run in runs],
        "raw_xml_files": [str(path) for path in xml_files],
        "disclaimer": DISCLAIMER,
        # None means no baseline was stated, so the unexpected-service rule was skipped.
        "expected_tcp_ports": None if expected_ports is None else sorted(expected_ports),
        "summary": {
            # None means discovery was not performed (single explicit host).
            "hosts_discovered_up": None if discovered is None else len(discovered),
            "hosts_scanned": len(scanned),
            "open_ports": sum(1 for h in scanned for s in h.services if s.state == "open"),
            "findings_by_classification": counts,
            "hosts_warranting_review": len(assessments),
        },
        "discovered_hosts": None if discovered is None else [asdict(h) for h in discovered],
        "hosts": [asdict(host) for host in scanned],
        "host_assessments": [asdict(assessment) for assessment in assessments],
        "findings": [asdict(finding) for finding in findings],
        "scope_notes": notes,
    }


def show(value: object) -> str:
    """Display a possibly-missing value honestly."""
    return NOT_REPORTED if value is None else str(value)


def describe_product(product: str | None, version: str | None, extra: str | None = None) -> str:
    """Combine product/version/extra info into one string, or say it was not reported."""
    text = " ".join(part for part in (product, version) if part)
    if extra:
        text = f"{text} ({extra})" if text else f"({extra})"
    return text or NOT_REPORTED


def format_text_report(report: dict) -> str:
    """Render the report dictionary as a human-readable text report."""
    summary = report["summary"]
    baseline = report["expected_tcp_ports"]
    lines = [
        "Network Exposure Analysis Report",
        "================================",
        f"Scan started     : {report['scan_started']}",
        f"Scan finished    : {report['scan_finished']}",
        f"Requested target : {report['requested_target']} ({report['target_type']})",
        f"Nmap version     : {show(report['nmap_version'])}",
        "Nmap commands    :",
        *[f"  {show(command)}" for command in report["nmap_commands"]],
        "Raw Nmap XML     :",
        *[f"  {path}" for path in report["raw_xml_files"]],
        "Expected TCP baseline: "
        + ("not stated (unexpected-service rule skipped)" if baseline is None
           else ", ".join(str(port) for port in baseline)),
        "",
        f"NOTE: {report['disclaimer']}",
        "",
        "Summary",
        "-------",
        "Hosts discovered (up) : "
        + ("discovery not performed" if summary["hosts_discovered_up"] is None
           else str(summary["hosts_discovered_up"])),
        f"Hosts scanned         : {summary['hosts_scanned']}",
        f"Open TCP ports        : {summary['open_ports']}",
        "Findings              : "
        + ", ".join(f"{level}={n}" for level, n in summary["findings_by_classification"].items()),
        f"Hosts warranting review: {summary['hosts_warranting_review']}",
        "",
    ]

    if report["discovered_hosts"] is not None:
        lines += ["Discovered hosts", "----------------"]
        if not report["discovered_hosts"]:
            lines.append("No live hosts were discovered.")
        for host in report["discovered_hosts"]:
            lines.append(
                f"{host['ip']}  hostname: {show(host['hostname'])}  "
                f"status: {host['status']} (reason: {show(host['status_reason'])})"
            )
        lines.append("")

    lines += ["Hosts and services", "------------------"]
    if not report["hosts"]:
        lines.append("No hosts were scanned.")
    for host in report["hosts"]:
        lines.append(
            f"{host['ip']}  hostname: {show(host['hostname'])}  "
            f"status: {host['status']} (reason: {show(host['status_reason'])})"
        )
        if host["unlisted_ports"]:
            summary_text = ", ".join(f"{state}={n}" for state, n in host["unlisted_ports"].items())
            lines.append(f"  Ports not listed individually: {summary_text}")
        if not host["services"]:
            lines.append("  No individually listed ports (no open ports found in the scanned range).")
        else:
            lines.append(f"  {'PORT':<11}{'STATE':<10}{'SERVICE':<16}PRODUCT / VERSION")
            for s in host["services"]:
                port = f"{s['port']}/{s['protocol']}"
                product = describe_product(s["product"], s["version"], s["extra_info"])
                lines.append(f"  {port:<11}{s['state']:<10}{show(s['name']):<16}{product}")
        lines.append("")

    lines += ["Host-level assessment", "---------------------"]
    if not report["host_assessments"]:
        lines.append("No host has findings that warrant review.")
    for a in report["host_assessments"]:
        lines += [
            f"[{a['classification']}] {a['ip']}  hostname: {show(a['hostname'])}",
            f"  Reason: {a['reason']}",
            "  Caused by:",
            *[f"    - {item}" for item in a["contributing_findings"]],
        ]
    lines.append("")

    lines += ["Findings", "--------"]
    if not report["findings"]:
        lines.append("No open ports were found, so there are no findings.")
    for f in report["findings"]:
        lines += [
            f"[{f['classification']}] {f['ip']}:{f['port']}/{f['protocol']}",
            f"  Hostname         : {show(f['hostname'])}",
            f"  Service          : {show(f['service'])}",
            f"  Product/version  : {describe_product(f['product'], f['version'])}",
            f"  Rules matched    : {', '.join(f['matched_rules']) or 'none'}",
            "  Reason(s):",
            *[f"    - {reason}" for reason in f["reasons"]],
            "  Recommended analyst follow-up:",
            *[f"    - {step}" for step in f["follow_ups"]],
        ]
        if f["note"]:
            lines.append(f"  Note: {f['note']}")
        lines.append("")

    lines += ["Scope and limitations", "---------------------"]
    lines += [f"- {note}" for note in report["scope_notes"]]
    return "\n".join(lines) + "\n"


def print_terminal_summary(report: dict) -> None:
    """Print a short summary of the results to the terminal."""
    summary = report["summary"]
    counts = summary["findings_by_classification"]
    print()
    print(f"=== Results for {report['requested_target']} ===")
    if summary["hosts_discovered_up"] is not None:
        print(f"Hosts discovered (up): {summary['hosts_discovered_up']}")
    print(f"Hosts scanned: {summary['hosts_scanned']}   Open TCP ports: {summary['open_ports']}")
    print("Findings: " + ", ".join(f"{level}={n}" for level, n in counts.items()))
    for f in report["findings"]:
        product = describe_product(f["product"], f["version"])
        print(f"  [{f['classification']:<11}] {f['ip']}:{f['port']}/{f['protocol']:<4} "
              f"{show(f['service'])} - {product}")
    if not report["findings"]:
        print("  No open ports found in the scanned range.")
    print(f"Hosts warranting review: {summary['hosts_warranting_review']}")
    for a in report["host_assessments"]:
        print(f"  [{a['classification']}] {a['ip']} - caused by: "
              + "; ".join(a["contributing_findings"]))
    print(f"\n{report['disclaimer']}")


def write_reports(report: dict, text: str, output_dir: Path, stamp: str) -> list[Path]:
    """Write the text and JSON reports. Never overwrites an existing file."""
    text_path = output_dir / f"report_{stamp}.txt"
    json_path = output_dir / f"report_{stamp}.json"
    try:
        # Mode "x" fails if the file already exists, protecting earlier reports.
        with text_path.open("x", encoding="utf-8") as handle:
            handle.write(text)
        with json_path.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        raise ScannerError(f"Could not write report files in {output_dir}: {exc}") from exc
    return [text_path, json_path]


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------


def prepare_output_dir(output_dir: Path) -> Path:
    """Create the reports directory if needed."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ScannerError(f"Could not create report directory {output_dir}: {exc}") from exc
    return output_dir


def run_scan(
    target: ipaddress.IPv4Address | ipaddress.IPv4Network,
    ports: str | None,
    output_dir: Path,
    expected_ports: set[int] | None = None,
) -> None:
    """Discovery -> enumeration -> parsing -> analysis -> reports."""
    output_dir = prepare_output_dir(output_dir)
    started = datetime.now().astimezone()
    stamp = started.strftime("%Y%m%d_%H%M%S")
    runs: list[NmapRun] = []
    xml_files: list[Path] = []

    # Stage 1: host discovery (networks only). A single explicitly named host
    # goes straight to enumeration.
    discovered: list[Host] | None = None
    if isinstance(target, ipaddress.IPv4Network):
        print(f"[*] Host discovery on {target}")
        discovery_xml = output_dir / f"discovery_{stamp}.xml"
        discovery_run = discover_hosts(target, discovery_xml)
        runs.append(discovery_run)
        xml_files.append(discovery_xml)
        discovered = [host for host in discovery_run.hosts if host.status == "up"]
        scan_targets = [host.ip for host in discovered]
        print(f"[*] Live hosts found: {len(scan_targets)}")
    else:
        scan_targets = [str(target)]

    # Stage 2: service/version enumeration on the selected hosts.
    scanned: list[Host] = []
    if scan_targets:
        print(f"[*] TCP service/version enumeration on {len(scan_targets)} host(s)")
        services_xml = output_dir / f"services_{stamp}.xml"
        service_run = enumerate_services(scan_targets, ports, services_xml)
        runs.append(service_run)
        xml_files.append(services_xml)
        scanned = service_run.hosts
    else:
        print("[!] No live hosts were discovered; skipping service enumeration.")

    # Stage 3: analysis and reporting.
    findings = analyze(scanned, expected_ports)
    notes = build_scope_notes(target, ports, scan_targets)
    finished = datetime.now().astimezone()
    report = build_report(
        target, started, finished, runs, xml_files, discovered, scanned, findings, notes,
        expected_ports,
    )
    report_paths = write_reports(report, format_text_report(report), output_dir, stamp)

    print_terminal_summary(report)
    print("\nFiles written:")
    for path in [*xml_files, *report_paths]:
        print(f"  {path}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Authorized exposure analysis of a private/lab IPv4 host or network using Nmap. "
            "Only RFC 1918 and loopback targets up to /24 are accepted."
        )
    )
    parser.add_argument("target", help="IPv4 address or CIDR network, e.g. 10.0.2.15 or 192.168.56.0/24")
    parser.add_argument("--ports", help="TCP ports to scan, e.g. 1-1024 or 22,80,8000 (default: Nmap top 1000)")
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_REPORT_DIR,
        help=f"directory for reports and raw XML (default: {DEFAULT_REPORT_DIR})",
    )
    parser.add_argument(
        "--expected-ports",
        help=(
            "expected-service baseline: TCP ports that are supposed to be open, e.g. 80,443. "
            "Open ports outside it get an unexpected-service REVIEW reason. "
            "If omitted, no baseline is assumed and that rule is skipped."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        target = validate_target(args.target)
        ports = validate_port_spec(args.ports) if args.ports else None
        expected_ports = (
            parse_expected_ports(args.expected_ports) if args.expected_ports is not None else None
        )
        require_nmap()
        run_scan(target, ports, args.output_dir, expected_ports)
    except ScannerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
