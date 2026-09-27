"""
Offline unit tests for network_scanner.py.

These tests never run Nmap and never touch the network.

All XML below is SYNTHETIC TEST DATA written by hand to follow the structure
of Nmap's XML format (see /usr/share/nmap/nmap.dtd). It is NOT real scan
output and must not be treated as evidence. Real verification is done by
running the scanner against an approved lab target.

Run with:  python3 -m unittest -v test_network_scanner.py
"""

import ipaddress
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import network_scanner as ns

# SYNTHETIC TEST DATA - modelled on Nmap's XML format, not a real scan.
SYNTHETIC_SERVICE_SCAN_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -oX synthetic.xml 192.168.99.10 192.168.99.20"
         version="7.98" xmloutputversion="1.05">
  <host>
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.99.10" addrtype="ipv4"/>
    <hostnames><hostname name="devbox.lab" type="PTR"/></hostnames>
    <ports>
      <extraports state="closed" count="995"/>
      <port protocol="tcp" portid="8000">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="SimpleHTTPServer" version="0.6"
                 extrainfo="Python 3.14.4" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="telnet" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="nginx" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
      </port>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ftp" tunnel="ssl" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="filtered" reason="no-response" reason_ttl="0"/>
        <service name="mysql" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="631">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ipp" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="notanumber">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.99.20" addrtype="ipv4"/>
    <hostnames/>
    <ports><extraports state="closed" count="1000"/></ports>
  </host>
  <host>
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
  </host>
  <runstats><finished time="0" elapsed="1.0" exit="success"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>
"""

# SYNTHETIC TEST DATA - a ping-scan (-sn) style result with no open ports section.
SYNTHETIC_DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn -oX synthetic.xml 192.168.99.0/24" version="7.98" xmloutputversion="1.05">
  <host>
    <status state="up" reason="conn-refused" reason_ttl="0"/>
    <address addr="192.168.99.10" addrtype="ipv4"/>
  </host>
  <host>
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.99.11" addrtype="ipv4"/>
  </host>
  <runstats><finished time="0" elapsed="1.0" exit="success"/><hosts up="1" down="1" total="2"/></runstats>
</nmaprun>
"""

# SYNTHETIC TEST DATA - baseline and host-level scenarios, not a real scan.
#   .40  dev HTTP server on 8000 (outside baseline) + expected nginx on 80,
#        plus closed 443 and filtered 22 that must produce no finding
#   .50  only expected nginx on 80 (INFO) -> no host-level review
#   .60  up, but no open ports -> being alive is not a finding
SYNTHETIC_BASELINE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -oX synthetic.xml 192.168.99.40 192.168.99.50 192.168.99.60"
         version="7.98" xmloutputversion="1.05">
  <host>
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.99.40" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8000">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="SimpleHTTPServer" version="0.6" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="nginx" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="conn-refused" reason_ttl="0"/>
        <service name="https" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="filtered" reason="no-response" reason_ttl="0"/>
        <service name="ssh" method="table" conf="3"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.99.50" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="999"/>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="nginx" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="user-set" reason_ttl="0"/>
    <address addr="192.168.99.60" addrtype="ipv4"/>
    <ports><extraports state="closed" count="1000"/></ports>
  </host>
  <runstats><finished time="0" elapsed="1.0" exit="success"/><hosts up="3" down="0" total="3"/></runstats>
</nmaprun>
"""

# Stated lab baseline used by the tests below, matching the planned validation run.
SYNTHETIC_EXPECTED_PORTS = {80, 443}


class TestTargetValidation(unittest.TestCase):
    def test_accepts_private_and_loopback_targets(self):
        self.assertEqual(ns.validate_target("10.0.2.15"), ipaddress.ip_address("10.0.2.15"))
        self.assertEqual(ns.validate_target(" 127.0.0.1 "), ipaddress.ip_address("127.0.0.1"))
        self.assertEqual(ns.validate_target("192.168.56.0/24"), ipaddress.ip_network("192.168.56.0/24"))
        self.assertEqual(ns.validate_target("172.16.5.0/28"), ipaddress.ip_network("172.16.5.0/28"))

    def test_slash_32_is_treated_as_single_host(self):
        self.assertEqual(ns.validate_target("10.0.2.15/32"), ipaddress.ip_address("10.0.2.15"))

    def test_rejects_public_and_other_ranges(self):
        for text in ("8.8.8.8", "1.1.1.0/24", "172.32.0.1", "100.64.0.1", "224.0.0.1", "0.0.0.0"):
            with self.subTest(text=text):
                with self.assertRaises(ns.TargetError):
                    ns.validate_target(text)

    def test_rejects_networks_larger_than_slash_24(self):
        with self.assertRaisesRegex(ns.TargetError, "larger than /24"):
            ns.validate_target("10.0.0.0/16")
        # Host bits set AND too large: report the size problem, not a /16 suggestion.
        with self.assertRaisesRegex(ns.TargetError, "larger than /24"):
            ns.validate_target("10.0.2.0/16")

    def test_rejects_host_bits_set_with_suggestion(self):
        with self.assertRaisesRegex(ns.TargetError, "10.0.2.0/24"):
            ns.validate_target("10.0.2.15/24")

    def test_rejects_invalid_text_hostnames_and_ipv6(self):
        for text in ("", "abc", "example.com", "10.0.2", "999.1.1.1", "::1", "10.0.2.15; rm -rf /"):
            with self.subTest(text=text):
                with self.assertRaises(ns.TargetError):
                    ns.validate_target(text)


class TestPortSpecValidation(unittest.TestCase):
    def test_valid_specs(self):
        for spec in ("22", "1-1024", "22,80,8000-8100"):
            with self.subTest(spec=spec):
                self.assertEqual(ns.validate_port_spec(spec), spec)

    def test_invalid_specs(self):
        for spec in ("", "0", "70000", "100-10", "22,", "-p-", "22 80", "T:22"):
            with self.subTest(spec=spec):
                with self.assertRaises(ns.TargetError):
                    ns.validate_port_spec(spec)


class TestXmlParsing(unittest.TestCase):
    def setUp(self):
        self.run = ns.parse_nmap_xml(SYNTHETIC_SERVICE_SCAN_XML)
        self.hosts = {host.ip: host for host in self.run.hosts}

    def test_run_metadata(self):
        self.assertEqual(self.run.nmap_version, "7.98")
        self.assertTrue(self.run.command.startswith("nmap -sT -sV -Pn"))

    def test_mac_only_host_is_skipped(self):
        self.assertEqual(sorted(self.hosts), ["192.168.99.10", "192.168.99.20"])

    def test_host_fields(self):
        host = self.hosts["192.168.99.10"]
        self.assertEqual(host.hostname, "devbox.lab")
        self.assertEqual(host.status, "up")
        self.assertEqual(host.status_reason, "user-set")
        self.assertEqual(host.unlisted_ports, {"closed": 995})

    def test_missing_hostname_is_none(self):
        host = self.hosts["192.168.99.20"]
        self.assertIsNone(host.hostname)
        self.assertEqual(host.services, [])
        self.assertEqual(host.unlisted_ports, {"closed": 1000})

    def test_service_fields(self):
        services = {s.port: s for s in self.hosts["192.168.99.10"].services}
        dev = services[8000]
        self.assertEqual((dev.protocol, dev.state, dev.name), ("tcp", "open", "http"))
        self.assertEqual((dev.product, dev.version, dev.extra_info), ("SimpleHTTPServer", "0.6", "Python 3.14.4"))
        self.assertEqual(dev.detection_method, "probed")

    def test_missing_optional_service_fields_are_none(self):
        services = {s.port: s for s in self.hosts["192.168.99.10"].services}
        self.assertIsNone(services[23].product)
        self.assertIsNone(services[23].version)
        no_service = services[9999]  # <port> with no <service> element at all
        self.assertIsNone(no_service.name)
        self.assertIsNone(no_service.product)
        self.assertIsNone(no_service.detection_method)

    def test_malformed_port_entry_is_skipped(self):
        ports = [s.port for s in self.hosts["192.168.99.10"].services]
        self.assertEqual(len(ports), 8)  # 9 <port> elements, one with portid="notanumber"

    def test_discovery_output_without_ports(self):
        run = ns.parse_nmap_xml(SYNTHETIC_DISCOVERY_XML)
        states = {host.ip: host.status for host in run.hosts}
        self.assertEqual(states, {"192.168.99.10": "up", "192.168.99.11": "down"})
        self.assertIsNone(run.hosts[0].hostname)
        self.assertEqual(run.hosts[0].services, [])

    def test_malformed_xml_raises_clear_error(self):
        truncated = SYNTHETIC_SERVICE_SCAN_XML[:400]  # like an interrupted Nmap run
        with self.assertRaisesRegex(ns.NmapXmlError, "malformed or incomplete"):
            ns.parse_nmap_xml(truncated)

    def test_wrong_root_element_raises(self):
        with self.assertRaisesRegex(ns.NmapXmlError, "expected <nmaprun>"):
            ns.parse_nmap_xml("<html><body>not nmap</body></html>")

    def test_nmap_reported_error_raises(self):
        xml = ('<nmaprun scanner="nmap" version="7.98" xmloutputversion="1.05">'
               '<runstats><finished time="0" elapsed="0" exit="error" errormsg="synthetic failure"/>'
               '<hosts total="0"/></runstats></nmaprun>')
        with self.assertRaisesRegex(ns.NmapXmlError, "synthetic failure"):
            ns.parse_nmap_xml(xml)

    def test_unreadable_file_raises(self):
        with self.assertRaises(ns.NmapXmlError):
            ns.parse_nmap_xml_file(Path("/nonexistent/synthetic.xml"))


class TestAnalysis(unittest.TestCase):
    def setUp(self):
        hosts = ns.parse_nmap_xml(SYNTHETIC_SERVICE_SCAN_XML).hosts
        self.findings = ns.analyze(hosts)
        self.by_port = {f.port: f for f in self.findings}

    def test_one_finding_per_open_port_only(self):
        # Open ports: 8000, 23, 22, 80, 9999, 21, 631. 3306 is filtered -> no finding.
        self.assertEqual(sorted(self.by_port), [21, 22, 23, 80, 631, 8000, 9999])
        self.assertEqual(len(self.findings), len(self.by_port))  # no duplicate findings

    def test_dev_http_server_is_review_with_both_reasons(self):
        f = self.by_port[8000]
        self.assertEqual(f.classification, ns.REVIEW)
        self.assertEqual(f.matched_rules, ["dev-web-server", "http-nonstandard-port"])
        self.assertEqual(len(f.reasons), 2)
        self.assertIn("development/testing web server", f.reasons[0])
        self.assertIn("bind it to 127.0.0.1", f.follow_ups[0])

    def test_telnet_is_high_review(self):
        self.assertEqual(self.by_port[23].classification, ns.HIGH_REVIEW)
        self.assertEqual(self.by_port[23].matched_rules, ["plaintext-remote-login"])

    def test_ftp_over_tls_is_not_flagged_as_plaintext(self):
        self.assertEqual(self.by_port[21].classification, ns.INFO)
        self.assertEqual(self.by_port[21].matched_rules, [])

    def test_ssh_is_review(self):
        self.assertEqual(self.by_port[22].classification, ns.REVIEW)

    def test_http_on_port_80_is_info(self):
        self.assertEqual(self.by_port[80].classification, ns.INFO)

    def test_missing_service_name_is_unidentified(self):
        self.assertEqual(self.by_port[9999].matched_rules, ["unidentified-service"])

    def test_table_guess_gets_a_note(self):
        self.assertEqual(self.by_port[631].note, ns.TABLE_METHOD_NOTE)
        self.assertIsNone(self.by_port[8000].note)

    def test_highest_classification_wins_and_sort_order(self):
        # A service matching both a HIGH REVIEW and a REVIEW rule gets HIGH REVIEW.
        service = ns.Service(8080, "tcp", "open", None, "telnet", "WEBrick", None, None, None, "probed")
        host = ns.Host("192.168.99.30", None, "up", None, [service])
        [finding] = ns.analyze([host])
        self.assertEqual(finding.classification, ns.HIGH_REVIEW)
        self.assertEqual(len(finding.reasons), 2)
        # Findings are sorted HIGH REVIEW first.
        self.assertEqual(self.findings[0].classification, ns.HIGH_REVIEW)

    def test_no_hosts_means_no_findings(self):
        self.assertEqual(ns.analyze([]), [])

    def test_findings_never_claim_confirmed_compromise(self):
        wording = " ".join(r["reason"] + r["follow_up"] for r in ns.REVIEW_RULES).lower()
        for word in ("malicious", "compromised", "attack", "infected", "exploit"):
            self.assertNotIn(word, wording)


class TestExpectedServiceBaseline(unittest.TestCase):
    def setUp(self):
        self.hosts = ns.parse_nmap_xml(SYNTHETIC_BASELINE_XML).hosts
        findings = ns.analyze(self.hosts, SYNTHETIC_EXPECTED_PORTS)
        self.by_key = {(f.ip, f.port): f for f in findings}

    def test_parse_expected_ports(self):
        self.assertEqual(ns.parse_expected_ports("80,443"), {80, 443})
        self.assertEqual(ns.parse_expected_ports("22,8000-8002"), {22, 8000, 8001, 8002})
        for spec in ("", "abc", "0", "443-80"):
            with self.subTest(spec=spec):
                with self.assertRaises(ns.TargetError):
                    ns.parse_expected_ports(spec)

    def test_expected_service_gets_no_unexpected_finding(self):
        f = self.by_key[("192.168.99.40", 80)]
        self.assertNotIn("unexpected-service", f.matched_rules)
        self.assertEqual(f.classification, ns.INFO)

    def test_unexpected_open_service_is_review(self):
        # Port 631 matches no service rule, so REVIEW comes only from the baseline.
        service = ns.Service(631, "tcp", "open", None, "ipp", "CUPS", None, None, None, "probed")
        host = ns.Host("192.168.99.70", None, "up", None, [service])
        [finding] = ns.analyze([host], SYNTHETIC_EXPECTED_PORTS)
        self.assertEqual(finding.classification, ns.REVIEW)
        self.assertEqual(finding.matched_rules, ["unexpected-service"])
        self.assertIn("outside the expected-service baseline", finding.reasons[0])

    def test_simplehttpserver_on_8000_is_review_with_separate_reasons(self):
        f = self.by_key[("192.168.99.40", 8000)]
        self.assertEqual(f.classification, ns.REVIEW)
        self.assertEqual(
            f.matched_rules, ["dev-web-server", "http-nonstandard-port", "unexpected-service"]
        )
        self.assertEqual(len(f.reasons), 3)

    def test_simplehttpserver_is_review_even_without_baseline(self):
        findings = ns.analyze(self.hosts)  # no baseline stated
        f = next(f for f in findings if f.port == 8000)
        self.assertEqual(f.classification, ns.REVIEW)
        self.assertEqual(f.matched_rules, ["dev-web-server", "http-nonstandard-port"])

    def test_no_baseline_means_rule_is_skipped(self):
        findings = ns.analyze(self.hosts, None)
        self.assertFalse(any("unexpected-service" in f.matched_rules for f in findings))

    def test_closed_and_filtered_ports_produce_no_finding(self):
        self.assertNotIn(("192.168.99.40", 443), self.by_key)  # closed
        self.assertNotIn(("192.168.99.40", 22), self.by_key)   # filtered, outside baseline
        self.assertEqual(len(self.by_key), 3)  # .40:8000, .40:80, .50:80

    def test_baseline_wording_never_claims_compromise(self):
        rule = ns.UNEXPECTED_SERVICE_RULE
        wording = rule["reason"] + rule["follow_up"]
        for word in ("malicious", "compromise", "attack", "infected", "exploit", "vulnerab"):
            self.assertNotIn(word, wording.lower())


class TestHostAssessment(unittest.TestCase):
    def setUp(self):
        self.hosts = ns.parse_nmap_xml(SYNTHETIC_BASELINE_XML).hosts
        findings = ns.analyze(self.hosts, SYNTHETIC_EXPECTED_PORTS)
        self.assessments = {a.ip: a for a in ns.assess_hosts(self.hosts, findings)}

    def test_host_with_review_finding_gets_host_level_review(self):
        a = self.assessments["192.168.99.40"]
        self.assertEqual(a.classification, ns.REVIEW)
        self.assertEqual(
            a.contributing_findings,
            ["8000/tcp [REVIEW] dev-web-server, http-nonstandard-port, unexpected-service"],
        )
        self.assertIn("1 exposed service(s)", a.reason)

    def test_host_with_only_info_findings_gets_no_host_review(self):
        self.assertNotIn("192.168.99.50", self.assessments)

    def test_host_that_is_merely_up_gets_no_host_review(self):
        self.assertNotIn("192.168.99.60", self.assessments)
        self.assertEqual(list(self.assessments), ["192.168.99.40"])

    def test_high_review_findings_are_listed_as_causes(self):
        hosts = ns.parse_nmap_xml(SYNTHETIC_SERVICE_SCAN_XML).hosts
        [a] = ns.assess_hosts(hosts, ns.analyze(hosts))
        self.assertEqual(a.ip, "192.168.99.10")
        # Telnet (HIGH REVIEW), SSH, dev server, unidentified 9999 - not INFO ports 21/80/631.
        ports = [item.split("/")[0] for item in a.contributing_findings]
        self.assertEqual(ports, ["22", "23", "8000", "9999"])
        self.assertIn("23/tcp [HIGH REVIEW] plaintext-remote-login", a.contributing_findings)

    def test_host_assessment_wording_never_claims_compromise(self):
        text = " ".join(a.reason for a in self.assessments.values()).lower()
        for word in ("malicious", "compromise", "attack", "infected", "exploit", "vulnerab"):
            self.assertNotIn(word, text)


class TestReporting(unittest.TestCase):
    def setUp(self):
        run = ns.parse_nmap_xml(SYNTHETIC_SERVICE_SCAN_XML)
        now = datetime(2026, 1, 1, 12, 0, 0).astimezone()
        self.report = ns.build_report(
            target=ipaddress.ip_address("192.168.99.10"),
            started=now, finished=now, runs=[run],
            xml_files=[Path("synthetic.xml")], discovered=None,
            scanned=run.hosts, findings=ns.analyze(run.hosts),
            notes=["synthetic note"],
        )

    def test_summary_counts(self):
        summary = self.report["summary"]
        self.assertIsNone(summary["hosts_discovered_up"])
        self.assertEqual(summary["hosts_scanned"], 2)
        self.assertEqual(summary["open_ports"], 7)
        self.assertEqual(summary["findings_by_classification"],
                         {"HIGH REVIEW": 1, "REVIEW": 3, "INFO": 3})

    def test_text_report_shows_missing_values_honestly(self):
        text = ns.format_text_report(self.report)
        self.assertIn("hostname: not reported by Nmap", text)
        self.assertIn("discovery not performed", text)
        self.assertIn("[REVIEW] 192.168.99.10:8000/tcp", text)
        self.assertIn(ns.DISCLAIMER, text)

    def test_reports_written_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            text = ns.format_text_report(self.report)
            text_path, json_path = ns.write_reports(self.report, text, out, "synthetic")
            self.assertTrue(text_path.is_file())
            loaded = json.loads(json_path.read_text())
            self.assertEqual(loaded["requested_target"], "192.168.99.10")
            self.assertIsNone(loaded["hosts"][1]["hostname"])  # JSON keeps missing values as null
            with self.assertRaises(ns.ScannerError):
                ns.write_reports(self.report, text, out, "synthetic")

    def test_host_assessment_in_report_without_baseline(self):
        self.assertIsNone(self.report["expected_tcp_ports"])
        self.assertEqual(self.report["summary"]["hosts_warranting_review"], 1)
        text = ns.format_text_report(self.report)
        self.assertIn("Expected TCP baseline: not stated (unexpected-service rule skipped)", text)
        self.assertIn("Host-level assessment", text)
        self.assertIn("[REVIEW] 192.168.99.10  hostname: devbox.lab", text)

    def test_baseline_and_host_assessment_in_json_and_text(self):
        run = ns.parse_nmap_xml(SYNTHETIC_BASELINE_XML)
        now = datetime(2026, 1, 1, 12, 0, 0).astimezone()
        report = ns.build_report(
            target=ipaddress.ip_network("192.168.99.0/24"),
            started=now, finished=now, runs=[run],
            xml_files=[Path("synthetic.xml")], discovered=run.hosts,
            scanned=run.hosts, findings=ns.analyze(run.hosts, SYNTHETIC_EXPECTED_PORTS),
            notes=["synthetic note"], expected_ports=SYNTHETIC_EXPECTED_PORTS,
        )
        loaded = json.loads(json.dumps(report))  # must be JSON-serialisable
        self.assertEqual(loaded["expected_tcp_ports"], [80, 443])
        self.assertEqual(loaded["summary"]["hosts_warranting_review"], 1)
        [assessment] = loaded["host_assessments"]
        self.assertEqual(assessment["ip"], "192.168.99.40")
        self.assertEqual(assessment["classification"], "REVIEW")
        text = ns.format_text_report(report)
        self.assertIn("Expected TCP baseline: 80, 443", text)
        self.assertIn("8000/tcp [REVIEW] dev-web-server, http-nonstandard-port, unexpected-service", text)

    def test_text_report_when_no_host_warrants_review(self):
        report = dict(self.report, host_assessments=[])
        self.assertIn("No host has findings that warrant review.", ns.format_text_report(report))

    def test_unwritable_directory_raises_clear_error(self):
        with self.assertRaises(ns.ScannerError):
            ns.write_reports(self.report, "x", Path("/nonexistent/dir"), "synthetic")


class TestCommandLineErrors(unittest.TestCase):
    """main() must reject bad input with a message and exit code, never run Nmap."""

    def run_main(self, argv):
        guard = mock.patch.object(ns.subprocess, "run", side_effect=AssertionError("Nmap must not run"))
        with guard, mock.patch("sys.stderr") as stderr:
            code = ns.main(argv)
        return code, "".join(call.args[0] for call in stderr.write.call_args_list)

    def test_public_target_rejected(self):
        code, err = self.run_main(["8.8.8.8"])
        self.assertEqual(code, 1)
        self.assertIn("outside the allowed lab ranges", err)

    def test_invalid_target_rejected(self):
        code, err = self.run_main(["not-an-ip"])
        self.assertEqual(code, 1)
        self.assertIn("not a valid IPv4", err)

    def test_invalid_ports_rejected(self):
        code, err = self.run_main(["10.0.2.15", "--ports", "1-99999"])
        self.assertEqual(code, 1)
        self.assertIn("Invalid port", err)

    def test_public_network_rejected_even_with_baseline(self):
        code, err = self.run_main(["1.1.1.0/24", "--expected-ports", "80,443"])
        self.assertEqual(code, 1)
        self.assertIn("outside the allowed lab ranges", err)

    def test_invalid_expected_ports_rejected(self):
        code, err = self.run_main(["10.0.2.15", "--expected-ports", "http"])
        self.assertEqual(code, 1)
        self.assertIn("Invalid port list", err)

    def test_expected_ports_reach_the_scan(self):
        with mock.patch.object(ns.shutil, "which", return_value="/usr/bin/nmap"), \
             mock.patch.object(ns, "run_scan") as run_scan:
            self.assertEqual(ns.main(["10.0.2.15", "--expected-ports", "80,443"]), 0)
            self.assertEqual(run_scan.call_args.args[3], {80, 443})
            ns.main(["10.0.2.15"])
            self.assertIsNone(run_scan.call_args.args[3])  # no baseline assumed

    def test_missing_nmap_reported(self):
        with mock.patch.object(ns.shutil, "which", return_value=None):
            code, err = self.run_main(["10.0.2.15"])
        self.assertEqual(code, 1)
        self.assertIn("Nmap is not installed", err)


if __name__ == "__main__":
    unittest.main()
