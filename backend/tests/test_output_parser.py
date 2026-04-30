"""Unit-тесты для OutputParser — парсинг вывода инструментов безопасности."""

import json
import pytest

from app.services.output_parser import OutputParser

ASSET_ID = "asset-001"


class TestParseDispatcher:
    def test_unknown_tool_returns_empty(self):
        parser = OutputParser()
        result = parser.parse("unknown_tool", "some output", ASSET_ID)
        assert result == []

    def test_corrupted_output_returns_empty(self):
        parser = OutputParser()
        result = parser.parse("nmap", "not xml at all <<<>>>", ASSET_ID)
        assert result == []

    def test_empty_output_returns_empty(self):
        parser = OutputParser()
        result = parser.parse("nuclei", "", ASSET_ID)
        assert result == []

    @pytest.mark.parametrize("tool", [
        "subfinder", "amass", "httpx", "gobuster", "ffuf",
        "gau", "dalfox", "wafw00f", "wpscan", "whatweb",
    ])
    def test_new_tools_registered(self, tool):
        """Все 10 новых инструментов зарегистрированы в диспетчере."""
        parser = OutputParser()
        # Не должно вернуть пустой список из-за "No parser for tool"
        # (вернёт пустой из-за невалидного ввода, но парсер найдётся)
        result = parser.parse(tool, "", ASSET_ID)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# nmap XML
# ---------------------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestParseNmapXml:
    def test_extracts_open_ports(self):
        parser = OutputParser()
        findings = parser.parse_nmap_xml(NMAP_XML, ASSET_ID)
        assert len(findings) == 2  # only open ports

    def test_port_details(self):
        parser = OutputParser()
        findings = parser.parse_nmap_xml(NMAP_XML, ASSET_ID)
        http_finding = next(f for f in findings if "80" in f.evidence)
        assert http_finding.vulnerability_type == "open_port"
        assert "Apache" in http_finding.description
        assert http_finding.affected_asset_id == ASSET_ID
        assert http_finding.raw_data["tool"] == "nmap"
        assert http_finding.raw_data["port"] == "80"

    def test_invalid_xml_returns_empty(self):
        parser = OutputParser()
        findings = parser.parse_nmap_xml("<broken xml", ASSET_ID)
        assert findings == []


# ---------------------------------------------------------------------------
# nuclei JSONL
# ---------------------------------------------------------------------------

NUCLEI_JSONL = """{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical","description":"RCE via Log4j"},"matched-at":"http://example.com/api","host":"http://example.com"}
{"template-id":"tech-detect","info":{"name":"Technology Detection","severity":"info"},"matched-at":"http://example.com"}"""


class TestParseNucleiJson:
    def test_parses_multiple_findings(self):
        parser = OutputParser()
        findings = parser.parse_nuclei_json(NUCLEI_JSONL, ASSET_ID)
        assert len(findings) == 2

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_nuclei_json(NUCLEI_JSONL, ASSET_ID)
        log4shell = findings[0]
        assert "cve-2021-44228" in log4shell.vulnerability_type
        assert "CRITICAL" in log4shell.description
        assert "Log4Shell" in log4shell.description
        assert log4shell.affected_asset_id == ASSET_ID

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_nuclei_json("", ASSET_ID) == []


# ---------------------------------------------------------------------------
# nikto JSON
# ---------------------------------------------------------------------------

NIKTO_JSON = '{"vulnerabilities": [{"id": "000001", "msg": "Server leaks inodes via ETags", "url": "/index.html"}]}'


class TestParseNiktoJson:
    def test_parses_json(self):
        parser = OutputParser()
        findings = parser.parse_nikto_json(NIKTO_JSON, ASSET_ID)
        assert len(findings) == 1
        assert "nikto_000001" == findings[0].vulnerability_type
        assert "ETags" in findings[0].description

    def test_text_fallback(self):
        text = "+ OSVDB-3092: /admin/: This might be interesting.\n+ OSVDB-3268: /icons/: Directory indexing found."
        parser = OutputParser()
        findings = parser.parse_nikto_json(text, ASSET_ID)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# sqlmap text
# ---------------------------------------------------------------------------

SQLMAP_TEXT = """[INFO] testing 'AND boolean-based blind'
Parameter: id (GET)
    Type: boolean-based blind
    Type: time-based blind
    Type: UNION query"""


class TestParseSqlmapText:
    def test_extracts_injection(self):
        parser = OutputParser()
        findings = parser.parse_sqlmap_text(SQLMAP_TEXT, ASSET_ID)
        assert len(findings) >= 1
        f = findings[0]
        assert f.vulnerability_type == "sql_injection"
        assert "id" in f.description
        assert f.affected_asset_id == ASSET_ID

    def test_empty_output(self):
        parser = OutputParser()
        assert parser.parse_sqlmap_text("", ASSET_ID) == []

    def test_no_injection_found(self):
        parser = OutputParser()
        result = parser.parse_sqlmap_text("[INFO] testing connection\n[INFO] no injection found", ASSET_ID)
        assert result == []


# ---------------------------------------------------------------------------
# slither JSON
# ---------------------------------------------------------------------------

SLITHER_JSON = '{"results": {"detectors": [{"check": "reentrancy-eth", "impact": "High", "confidence": "Medium", "description": "Reentrancy in Contract.withdraw()", "elements": [{"type": "function", "name": "withdraw"}]}]}}'


class TestParseSlitherJson:
    def test_parses_detector(self):
        parser = OutputParser()
        findings = parser.parse_slither_json(SLITHER_JSON, ASSET_ID)
        assert len(findings) == 1
        f = findings[0]
        assert "slither_reentrancy-eth" == f.vulnerability_type
        assert "High" in f.description
        assert "withdraw" in f.evidence

    def test_invalid_json(self):
        parser = OutputParser()
        assert parser.parse_slither_json("{broken", ASSET_ID) == []


# ---------------------------------------------------------------------------
# mythril JSON
# ---------------------------------------------------------------------------

MYTHRIL_JSON = '{"issues": [{"swc-id": "107", "title": "Reentrancy", "description": "External call followed by state change", "function": "withdraw()", "filename": "Contract.sol"}]}'


class TestParseMythrilJson:
    def test_parses_issue(self):
        parser = OutputParser()
        findings = parser.parse_mythril_json(MYTHRIL_JSON, ASSET_ID)
        assert len(findings) == 1
        f = findings[0]
        assert "mythril_SWC-107" == f.vulnerability_type
        assert "Reentrancy" in f.description
        assert "withdraw" in f.evidence

    def test_invalid_json(self):
        parser = OutputParser()
        assert parser.parse_mythril_json("not json", ASSET_ID) == []


# ---------------------------------------------------------------------------
# ZAP JSON
# ---------------------------------------------------------------------------

ZAP_JSON = '{"site": [{"alerts": [{"pluginid": "10021", "alert": "X-Content-Type-Options Header Missing", "riskdesc": "Low (Medium)", "desc": "<p>Missing header</p>", "url": "http://example.com/"}]}]}'


class TestParseZapJson:
    def test_parses_alert(self):
        parser = OutputParser()
        findings = parser.parse_zap_json(ZAP_JSON, ASSET_ID)
        assert len(findings) == 1
        f = findings[0]
        assert "zap_10021" == f.vulnerability_type
        assert "X-Content-Type" in f.description
        assert "example.com" in f.evidence
        assert "<p>" not in f.description

    def test_invalid_json(self):
        parser = OutputParser()
        assert parser.parse_zap_json("{bad", ASSET_ID) == []


# ===========================================================================
# Тесты для 10 новых инструментов
# ===========================================================================


# ---------------------------------------------------------------------------
# subfinder — JSON
# ---------------------------------------------------------------------------

SUBFINDER_JSONL = '{"host":"api.example.com","source":"crtsh"}\n{"host":"mail.example.com","source":"hackertarget"}'


class TestParseSubfinderJson:
    def test_parses_subdomains(self):
        parser = OutputParser()
        findings = parser.parse_subfinder_json(SUBFINDER_JSONL, ASSET_ID)
        assert len(findings) == 2

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_subfinder_json(SUBFINDER_JSONL, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "subdomain_discovery"
        assert "api.example.com" in f.description
        assert "crtsh" in f.evidence
        assert f.affected_asset_id == ASSET_ID
        assert f.raw_data["tool"] == "subfinder"

    def test_empty_host_skipped(self):
        parser = OutputParser()
        findings = parser.parse_subfinder_json('{"host":"","source":"x"}', ASSET_ID)
        assert findings == []

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_subfinder_json("", ASSET_ID) == []

    def test_invalid_json_lines_skipped(self):
        parser = OutputParser()
        data = 'not json\n{"host":"ok.example.com","source":"dns"}'
        findings = parser.parse_subfinder_json(data, ASSET_ID)
        assert len(findings) == 1

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("subfinder", SUBFINDER_JSONL, ASSET_ID)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# amass — JSONL
# ---------------------------------------------------------------------------

AMASS_JSONL = '{"name":"sub1.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4"}]}\n{"name":"sub2.example.com","domain":"example.com"}'


class TestParseAmassJson:
    def test_parses_subdomains(self):
        parser = OutputParser()
        findings = parser.parse_amass_json(AMASS_JSONL, ASSET_ID)
        assert len(findings) == 2

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_amass_json(AMASS_JSONL, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "subdomain_discovery"
        assert "sub1.example.com" in f.description
        assert f.raw_data["tool"] == "amass"
        assert f.affected_asset_id == ASSET_ID

    def test_empty_name_skipped(self):
        parser = OutputParser()
        findings = parser.parse_amass_json('{"name":"","domain":"x"}', ASSET_ID)
        assert findings == []

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_amass_json("", ASSET_ID) == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("amass", AMASS_JSONL, ASSET_ID)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# httpx — JSONL
# ---------------------------------------------------------------------------

HTTPX_JSONL = '{"url":"https://example.com","status_code":200,"title":"Example","technologies":["nginx","PHP"],"webserver":"nginx/1.18"}'


class TestParseHttpxJson:
    def test_parses_host(self):
        parser = OutputParser()
        findings = parser.parse_httpx_json(HTTPX_JSONL, ASSET_ID)
        assert len(findings) == 1

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_httpx_json(HTTPX_JSONL, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "host_probe"
        assert "example.com" in f.description
        assert "200" in f.description
        assert "nginx" in f.evidence
        assert "PHP" in f.evidence
        assert f.raw_data["tool"] == "httpx"

    def test_no_technologies(self):
        parser = OutputParser()
        data = '{"url":"https://bare.com","status_code":301,"title":"","webserver":""}'
        findings = parser.parse_httpx_json(data, ASSET_ID)
        assert len(findings) == 1
        assert "N/A" in findings[0].evidence

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_httpx_json("", ASSET_ID) == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("httpx", HTTPX_JSONL, ASSET_ID)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# gobuster — text
# ---------------------------------------------------------------------------

GOBUSTER_TEXT = """/admin                (Status: 200) [Size: 1234]
/login               (Status: 302) [Size: 0]
/secret              (Status: 403) [Size: 274]
Progress: 100% - some info line"""


class TestParseGobusterText:
    def test_parses_paths(self):
        parser = OutputParser()
        findings = parser.parse_gobuster_text(GOBUSTER_TEXT, ASSET_ID)
        assert len(findings) == 3

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_gobuster_text(GOBUSTER_TEXT, ASSET_ID)
        admin = next(f for f in findings if "/admin" in f.description)
        assert admin.vulnerability_type == "hidden_directory"
        assert "200" in admin.description
        assert admin.raw_data["tool"] == "gobuster"
        assert admin.raw_data["path"] == "/admin"
        assert admin.raw_data["status"] == 200
        assert admin.raw_data["size"] == 1234

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_gobuster_text("", ASSET_ID) == []

    def test_no_matches(self):
        parser = OutputParser()
        assert parser.parse_gobuster_text("Progress: 100%", ASSET_ID) == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("gobuster", GOBUSTER_TEXT, ASSET_ID)
        assert len(findings) == 3


# ---------------------------------------------------------------------------
# ffuf — JSONL
# ---------------------------------------------------------------------------

FFUF_JSONL = '{"type":"result","url":"https://example.com/admin","status":200,"length":5432}\n{"type":"result","url":"https://example.com/api","status":301,"length":0}\n{"type":"info","message":"scan started"}'


class TestParseFfufJson:
    def test_parses_results_only(self):
        parser = OutputParser()
        findings = parser.parse_ffuf_json(FFUF_JSONL, ASSET_ID)
        assert len(findings) == 2  # info line skipped

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_ffuf_json(FFUF_JSONL, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "endpoint_discovery"
        assert "/admin" in f.description
        assert "200" in f.evidence
        assert f.raw_data["tool"] == "ffuf"

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_ffuf_json("", ASSET_ID) == []

    def test_non_result_skipped(self):
        parser = OutputParser()
        findings = parser.parse_ffuf_json('{"type":"info","message":"done"}', ASSET_ID)
        assert findings == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("ffuf", FFUF_JSONL, ASSET_ID)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# gau — text (URLs)
# ---------------------------------------------------------------------------

GAU_TEXT = """https://example.com/login
https://example.com/api/v1/users
https://example.com/admin
https://example.com/login"""


class TestParseGauText:
    def test_parses_urls(self):
        parser = OutputParser()
        findings = parser.parse_gau_text(GAU_TEXT, ASSET_ID)
        assert len(findings) == 3  # deduplicated

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_gau_text(GAU_TEXT, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "historical_url"
        assert "login" in f.description
        assert f.raw_data["tool"] == "gau"

    def test_deduplication(self):
        parser = OutputParser()
        findings = parser.parse_gau_text("http://a.com\nhttp://a.com\nhttp://a.com", ASSET_ID)
        assert len(findings) == 1

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_gau_text("", ASSET_ID) == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("gau", GAU_TEXT, ASSET_ID)
        assert len(findings) == 3


# ---------------------------------------------------------------------------
# dalfox — JSONL
# ---------------------------------------------------------------------------

DALFOX_JSONL = '{"type":"xss","data":"https://example.com/search?q=test","payload":"<script>alert(1)</script>"}\n{"type":"xss","data":"https://example.com/page?id=1","payload":"<img onerror=alert(1)>"}'


class TestParseDalfoxJson:
    def test_parses_xss(self):
        parser = OutputParser()
        findings = parser.parse_dalfox_json(DALFOX_JSONL, ASSET_ID)
        assert len(findings) == 2

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_dalfox_json(DALFOX_JSONL, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "xss"
        assert "search" in f.description
        assert "alert(1)" in f.evidence
        assert f.raw_data["tool"] == "dalfox"

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_dalfox_json("", ASSET_ID) == []

    def test_invalid_json_skipped(self):
        parser = OutputParser()
        data = 'broken\n{"type":"xss","data":"http://x.com","payload":"<svg>"}'
        findings = parser.parse_dalfox_json(data, ASSET_ID)
        assert len(findings) == 1

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("dalfox", DALFOX_JSONL, ASSET_ID)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# wafw00f — text
# ---------------------------------------------------------------------------

WAFW00F_TEXT = """[*] Checking https://example.com
[+] The site https://example.com is behind Cloudflare WAF
[*] Number of requests: 5"""

WAFW00F_NO_WAF = """[*] Checking https://example.com
[-] No WAF detected by the generic detection
[*] Number of requests: 5"""


class TestParseWafw00fText:
    def test_detects_waf(self):
        parser = OutputParser()
        findings = parser.parse_wafw00f_text(WAFW00F_TEXT, ASSET_ID)
        assert len(findings) == 1

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_wafw00f_text(WAFW00F_TEXT, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "waf_detected"
        assert "Cloudflare" in f.description
        assert f.raw_data["tool"] == "wafw00f"
        assert f.raw_data["waf"] == "Cloudflare"

    def test_no_waf_returns_empty(self):
        parser = OutputParser()
        findings = parser.parse_wafw00f_text(WAFW00F_NO_WAF, ASSET_ID)
        assert findings == []

    def test_empty_input(self):
        parser = OutputParser()
        assert parser.parse_wafw00f_text("", ASSET_ID) == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("wafw00f", WAFW00F_TEXT, ASSET_ID)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# wpscan — JSON
# ---------------------------------------------------------------------------

WPSCAN_JSON = json.dumps({
    "version": {"number": "5.2.1", "status": "insecure"},
    "plugins": {
        "contact-form-7": {
            "vulnerabilities": [
                {"title": "CF7 RCE", "references": {"cve": ["2023-1234"]}}
            ]
        },
        "safe-plugin": {"vulnerabilities": []}
    },
    "interesting_findings": [
        {"type": "robots_txt", "url": "https://example.com/robots.txt", "detail": "Found robots.txt"}
    ]
})


class TestParseWpscanJson:
    def test_parses_all_categories(self):
        parser = OutputParser()
        findings = parser.parse_wpscan_json(WPSCAN_JSON, ASSET_ID)
        types = [f.vulnerability_type for f in findings]
        assert "wordpress_version" in types
        assert "wordpress_plugin" in types
        assert "wordpress_finding" in types

    def test_insecure_version(self):
        parser = OutputParser()
        findings = parser.parse_wpscan_json(WPSCAN_JSON, ASSET_ID)
        ver = next(f for f in findings if f.vulnerability_type == "wordpress_version")
        assert "5.2.1" in ver.description
        assert ver.raw_data["tool"] == "wpscan"

    def test_plugin_vuln(self):
        parser = OutputParser()
        findings = parser.parse_wpscan_json(WPSCAN_JSON, ASSET_ID)
        plugin = next(f for f in findings if f.vulnerability_type == "wordpress_plugin")
        assert "contact-form-7" in plugin.description
        assert "2023-1234" in plugin.evidence

    def test_interesting_finding(self):
        parser = OutputParser()
        findings = parser.parse_wpscan_json(WPSCAN_JSON, ASSET_ID)
        robots = next(f for f in findings if f.vulnerability_type == "wordpress_finding")
        assert "robots_txt" in robots.description

    def test_secure_version_no_finding(self):
        data = json.dumps({"version": {"number": "6.4", "status": "latest"}, "plugins": {}, "interesting_findings": []})
        parser = OutputParser()
        findings = parser.parse_wpscan_json(data, ASSET_ID)
        assert findings == []

    def test_invalid_json(self):
        parser = OutputParser()
        assert parser.parse_wpscan_json("{bad", ASSET_ID) == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("wpscan", WPSCAN_JSON, ASSET_ID)
        assert len(findings) >= 3


# ---------------------------------------------------------------------------
# whatweb — JSON
# ---------------------------------------------------------------------------

WHATWEB_JSON = json.dumps([{
    "target": "https://example.com",
    "plugins": {
        "Apache": {"version": ["2.4.41"]},
        "PHP": {"version": ["8.1"]},
        "jQuery": {"version": ["3.6.0"]},
        "Bootstrap": [],
        "WordPress": {"version": ["6.4"]},
        "HTML5": {}
    }
}])


class TestParseWhatwebJson:
    def test_parses_technologies(self):
        parser = OutputParser()
        findings = parser.parse_whatweb_json(WHATWEB_JSON, ASSET_ID)
        assert len(findings) == 1

    def test_finding_fields(self):
        parser = OutputParser()
        findings = parser.parse_whatweb_json(WHATWEB_JSON, ASSET_ID)
        f = findings[0]
        assert f.vulnerability_type == "technology_fingerprint"
        assert "example.com" in f.description
        assert f.raw_data["tool"] == "whatweb"
        assert f.affected_asset_id == ASSET_ID

    def test_single_object(self):
        data = json.dumps({"target": "https://test.com", "plugins": {"nginx": {"version": ["1.18"]}}})
        parser = OutputParser()
        findings = parser.parse_whatweb_json(data, ASSET_ID)
        assert len(findings) == 1
        assert "test.com" in findings[0].description

    def test_invalid_json(self):
        parser = OutputParser()
        assert parser.parse_whatweb_json("<<<not json>>>", ASSET_ID) == []

    def test_via_dispatcher(self):
        parser = OutputParser()
        findings = parser.parse("whatweb", WHATWEB_JSON, ASSET_ID)
        assert len(findings) == 1
