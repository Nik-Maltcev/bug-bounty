"""Унифицированный парсер вывода инструментов безопасности.

Преобразует вывод каждого инструмента (XML/JSON/текст) в список RawFinding.
При ошибке парсинга возвращает пустой список и логирует ошибку.
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET

from app.models.schemas import RawFinding

logger = logging.getLogger(__name__)

_TOOL_PARSERS: dict[str, str] = {
    "nmap": "parse_nmap_xml",
    "nuclei": "parse_nuclei_json",
    "nikto": "parse_nikto_json",
    "sqlmap": "parse_sqlmap_text",
    "subfinder": "parse_subfinder_json",
    "amass": "parse_amass_json",
    "httpx": "parse_httpx_json",
    "gobuster": "parse_gobuster_text",
    "ffuf": "parse_ffuf_json",
    "gau": "parse_gau_text",
    "dalfox": "parse_dalfox_json",
    "wafw00f": "parse_wafw00f_text",
    "wpscan": "parse_wpscan_json",
    "whatweb": "parse_whatweb_json",
    "slither": "parse_slither_json",
    "mythril": "parse_mythril_json",
    "zap": "parse_zap_json",
}


class OutputParser:
    """Унифицированный парсер вывода инструментов безопасности."""

    def parse(self, tool_name: str, output: str, asset_id: str) -> list[RawFinding]:
        """Диспетчеризация по tool_name на конкретный парсер."""
        parser_method_name = _TOOL_PARSERS.get(tool_name)
        if parser_method_name is None:
            logger.error("No parser for tool: %s", tool_name)
            return []

        parser_method = getattr(self, parser_method_name)
        try:
            return parser_method(output, asset_id)
        except Exception:
            logger.exception("Parse error for tool %s", tool_name)
            return []

    # ------------------------------------------------------------------
    # nmap — XML
    # ------------------------------------------------------------------

    def parse_nmap_xml(self, xml_output: str, asset_id: str) -> list[RawFinding]:
        """Парсит XML-вывод nmap: порты, сервисы, версии."""
        findings: list[RawFinding] = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            logger.error("Invalid nmap XML output")
            return []

        for host in root.findall(".//host"):
            addr_el = host.find("address")
            host_addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            for port_el in host.findall(".//port"):
                port_id = port_el.get("portid", "")
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                if state != "open":
                    continue

                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                service_version = service_el.get("version", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""

                description = f"Open port {port_id}/{protocol}: {service_name}"
                if product:
                    description += f" ({product}"
                    if service_version:
                        description += f" {service_version}"
                    description += ")"

                findings.append(RawFinding(
                    vulnerability_type="open_port",
                    description=description,
                    evidence=f"{host_addr}:{port_id}/{protocol} - {service_name}",
                    affected_asset_id=asset_id,
                    raw_data={
                        "tool": "nmap",
                        "host": host_addr,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "version": service_version,
                        "product": product,
                    },
                ))

        return findings

    # ------------------------------------------------------------------
    # nuclei — JSONL
    # ------------------------------------------------------------------

    def parse_nuclei_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        """Парсит JSONL-вывод nuclei: template_id, severity, URL."""
        findings: list[RawFinding] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = item.get("template-id") or item.get("templateID", "unknown")
            severity = item.get("info", {}).get("severity", item.get("severity", "unknown"))
            matched_at = item.get("matched-at") or item.get("host", "")
            name = item.get("info", {}).get("name", item.get("name", template_id))
            description = item.get("info", {}).get("description", "")

            findings.append(RawFinding(
                vulnerability_type=f"nuclei_{template_id}",
                description=f"[{severity.upper()}] {name}: {description}" if description else f"[{severity.upper()}] {name}",
                evidence=f"Matched at: {matched_at}",
                affected_asset_id=asset_id,
                raw_data={"tool": "nuclei", **item},
            ))

        return findings

    # ------------------------------------------------------------------
    # nikto — JSON / text
    # ------------------------------------------------------------------

    def parse_nikto_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        """Парсит JSON/текстовый вывод nikto."""
        findings: list[RawFinding] = []

        # Try JSON first
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            # Fallback: parse text output
            return self._parse_nikto_text(json_output, asset_id)

        # nikto JSON can be a dict with "vulnerabilities" or a list
        vulns: list[dict] = []
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                # Some nikto versions use "host" → list of items
                for host_data in data.get("host", []):
                    if isinstance(host_data, dict):
                        vulns.extend(host_data.get("items", []))
        elif isinstance(data, list):
            vulns = data

        for vuln in vulns:
            vuln_id = str(vuln.get("id", vuln.get("OSVDB", "unknown")))
            desc = vuln.get("msg", vuln.get("description", "Nikto finding"))
            url = vuln.get("url", vuln.get("uri", ""))

            findings.append(RawFinding(
                vulnerability_type=f"nikto_{vuln_id}",
                description=desc,
                evidence=f"URL: {url}" if url else desc,
                affected_asset_id=asset_id,
                raw_data={"tool": "nikto", **vuln},
            ))

        return findings

    def _parse_nikto_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        """Fallback парсер для текстового вывода nikto."""
        findings: list[RawFinding] = []
        for line in text_output.strip().splitlines():
            line = line.strip()
            if line.startswith("+") and ":" in line:
                findings.append(RawFinding(
                    vulnerability_type="nikto_text_finding",
                    description=line.lstrip("+ "),
                    evidence=line,
                    affected_asset_id=asset_id,
                    raw_data={"tool": "nikto", "raw_line": line},
                ))
        return findings

    # ------------------------------------------------------------------
    # sqlmap — text
    # ------------------------------------------------------------------

    def parse_sqlmap_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        """Парсит текстовый вывод sqlmap: injection type, parameter, technique."""
        findings: list[RawFinding] = []

        # Pattern: "Parameter: <name> (<type>)"
        param_pattern = re.compile(
            r"Parameter:\s+(.+?)(?:\s+\((.+?)\))?$", re.MULTILINE
        )
        # Pattern: "Type: <injection_type>"
        type_pattern = re.compile(r"Type:\s+(.+?)$", re.MULTILINE)

        params = param_pattern.findall(text_output)
        types = type_pattern.findall(text_output)

        if params:
            for param_name, param_place in params:
                injection_types = ", ".join(types) if types else "SQL injection"
                findings.append(RawFinding(
                    vulnerability_type="sql_injection",
                    description=f"SQL injection in parameter '{param_name.strip()}' ({param_place.strip() or 'GET'}): {injection_types}",
                    evidence=f"Parameter: {param_name.strip()}, Types: {injection_types}",
                    affected_asset_id=asset_id,
                    raw_data={
                        "tool": "sqlmap",
                        "parameter": param_name.strip(),
                        "place": param_place.strip() if param_place else "GET",
                        "injection_types": types,
                    },
                ))
        elif re.search(r"is vulnerable|injection point", text_output, re.IGNORECASE):
            findings.append(RawFinding(
                vulnerability_type="sql_injection",
                description="Potential SQL injection detected by sqlmap",
                evidence=text_output[:500],
                affected_asset_id=asset_id,
                raw_data={"tool": "sqlmap", "raw_output": text_output[:2000]},
            ))

        return findings

    # ------------------------------------------------------------------
    # slither — JSON
    # ------------------------------------------------------------------

    def parse_slither_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        """Парсит JSON-вывод slither: detector, severity, functions."""
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            logger.error("Invalid slither JSON output")
            return []

        detectors = data if isinstance(data, list) else data.get("results", {}).get("detectors", [])

        for det in detectors:
            check = det.get("check", "unknown")
            impact = det.get("impact", "unknown")
            confidence = det.get("confidence", "unknown")
            description = det.get("description", "Slither finding")

            elements = det.get("elements", [])
            functions = [
                el.get("name", "")
                for el in elements
                if el.get("type") == "function"
            ]

            findings.append(RawFinding(
                vulnerability_type=f"slither_{check}",
                description=f"[{impact}/{confidence}] {description}",
                evidence=f"Detector: {check}, Functions: {', '.join(functions) or 'N/A'}",
                affected_asset_id=asset_id,
                raw_data={"tool": "slither", **det},
            ))

        return findings

    # ------------------------------------------------------------------
    # mythril — JSON
    # ------------------------------------------------------------------

    def parse_mythril_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        """Парсит JSON-вывод mythril: SWC-id, description, function, trace."""
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            logger.error("Invalid mythril JSON output")
            return []

        issues = data if isinstance(data, list) else data.get("issues", [])

        for issue in issues:
            swc_id = issue.get("swc-id", issue.get("swcID", "unknown"))
            title = issue.get("title", "Mythril finding")
            description = issue.get("description", "")
            function_name = issue.get("function", "unknown")
            filename = issue.get("filename", "")

            findings.append(RawFinding(
                vulnerability_type=f"mythril_SWC-{swc_id}",
                description=f"SWC-{swc_id}: {title} — {description}" if description else f"SWC-{swc_id}: {title}",
                evidence=f"Function: {function_name}, File: {filename}",
                affected_asset_id=asset_id,
                raw_data={"tool": "mythril", **issue},
            ))

        return findings

    # ------------------------------------------------------------------
    # OWASP ZAP — JSON
    # ------------------------------------------------------------------

    def parse_zap_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        """Парсит JSON-вывод OWASP ZAP: alert_id, risk_level, URL."""
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            logger.error("Invalid ZAP JSON output")
            return []

        # ZAP report structure: {"site": [{"alerts": [...]}]}
        alerts: list[dict] = []
        if isinstance(data, dict):
            for site in data.get("site", []):
                alerts.extend(site.get("alerts", []))
            # Also handle flat alerts list
            if not alerts:
                alerts = data.get("alerts", [])
        elif isinstance(data, list):
            alerts = data

        for alert in alerts:
            alert_id = str(alert.get("pluginid", alert.get("alertRef", "unknown")))
            risk = alert.get("riskdesc", alert.get("risk", "unknown"))
            name = alert.get("alert", alert.get("name", "ZAP finding"))
            desc = alert.get("desc", alert.get("description", ""))
            url = alert.get("url", "")

            # Clean HTML tags from description
            desc_clean = re.sub(r"<[^>]+>", "", desc).strip() if desc else name

            findings.append(RawFinding(
                vulnerability_type=f"zap_{alert_id}",
                description=f"[{risk}] {name}: {desc_clean}" if desc_clean != name else f"[{risk}] {name}",
                evidence=f"URL: {url}" if url else f"Alert: {name}",
                affected_asset_id=asset_id,
                raw_data={"tool": "zap", **alert},
            ))

        return findings

    # ------------------------------------------------------------------
    # subfinder — JSON
    # ------------------------------------------------------------------

    def parse_subfinder_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = item.get("host", "")
            source = item.get("source", "unknown")
            if host:
                findings.append(RawFinding(
                    vulnerability_type="subdomain_discovery",
                    description=f"Обнаружен поддомен: {host}",
                    evidence=f"Источник: {source}",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "subfinder", **item},
                ))
        return findings

    # ------------------------------------------------------------------
    # amass — JSONL
    # ------------------------------------------------------------------

    def parse_amass_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = item.get("name", "")
            if name:
                findings.append(RawFinding(
                    vulnerability_type="subdomain_discovery",
                    description=f"Обнаружен поддомен через OSINT: {name}",
                    evidence=f"Данные: {json.dumps(item)[:200]}",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "amass", **item},
                ))
        return findings

    # ------------------------------------------------------------------
    # httpx — JSONL
    # ------------------------------------------------------------------

    def parse_httpx_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = item.get("url", "")
            status_code = item.get("status_code", 0)
            title = item.get("title", "")
            tech = item.get("technologies", [])
            webserver = item.get("webserver", "")

            findings.append(RawFinding(
                vulnerability_type="host_probe",
                description=f"Живой хост: {url} (статус {status_code})",
                evidence=f"Заголовок: {title}, Сервер: {webserver}, Технологии: {', '.join(tech) if tech else 'N/A'}",
                affected_asset_id=asset_id,
                raw_data={"tool": "httpx", **item},
            ))
        return findings

    # ------------------------------------------------------------------
    # gobuster — text
    # ------------------------------------------------------------------

    def parse_gobuster_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        pattern = re.compile(r"(/[^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]")
        for line in text_output.strip().splitlines():
            match = pattern.search(line)
            if match:
                path, status, size = match.groups()
                findings.append(RawFinding(
                    vulnerability_type="hidden_directory",
                    description=f"Обнаружен скрытый путь: {path} (статус {status})",
                    evidence=f"Путь: {path}, Размер: {size} байт",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "gobuster", "path": path, "status": int(status), "size": int(size)},
                ))
        return findings

    # ------------------------------------------------------------------
    # ffuf — JSONL
    # ------------------------------------------------------------------

    def parse_ffuf_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("type") != "result":
                continue
            url = item.get("url", "")
            status = item.get("status", 0)
            length = item.get("length", 0)
            findings.append(RawFinding(
                vulnerability_type="endpoint_discovery",
                description=f"Обнаружен эндпоинт: {url} (статус {status})",
                evidence=f"Статус: {status}, Длина: {length}",
                affected_asset_id=asset_id,
                raw_data={"tool": "ffuf", **item},
            ))
        return findings

    # ------------------------------------------------------------------
    # gau — text (URLs)
    # ------------------------------------------------------------------

    def parse_gau_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        urls: set[str] = set()
        for line in text_output.strip().splitlines():
            url = line.strip()
            if url and url not in urls:
                urls.add(url)
                findings.append(RawFinding(
                    vulnerability_type="historical_url",
                    description=f"Исторический URL: {url}",
                    evidence=url,
                    affected_asset_id=asset_id,
                    raw_data={"tool": "gau", "url": url},
                ))
        return findings

    # ------------------------------------------------------------------
    # dalfox — JSONL
    # ------------------------------------------------------------------

    def parse_dalfox_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            vuln_type = item.get("type", "xss")
            data = item.get("data", "")
            payload = item.get("payload", "")
            findings.append(RawFinding(
                vulnerability_type="xss",
                description=f"Обнаружен XSS: {data}",
                evidence=f"Payload: {payload}",
                affected_asset_id=asset_id,
                raw_data={"tool": "dalfox", **item},
            ))
        return findings

    # ------------------------------------------------------------------
    # wafw00f — text
    # ------------------------------------------------------------------

    def parse_wafw00f_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in text_output.strip().splitlines():
            match = re.search(r"is behind\s+(.+?)\s+WAF", line, re.IGNORECASE)
            if match:
                waf_name = match.group(1).strip()
                findings.append(RawFinding(
                    vulnerability_type="waf_detected",
                    description=f"Обнаружен WAF: {waf_name}",
                    evidence=line.strip(),
                    affected_asset_id=asset_id,
                    raw_data={"tool": "wafw00f", "waf": waf_name},
                ))
        return findings

    # ------------------------------------------------------------------
    # wpscan — JSON
    # ------------------------------------------------------------------

    def parse_wpscan_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings

        # Version vulnerabilities
        version = data.get("version", {})
        if version and version.get("status") == "insecure":
            findings.append(RawFinding(
                vulnerability_type="wordpress_version",
                description=f"Устаревшая версия WordPress: {version.get('number', 'unknown')}",
                evidence=f"Статус: {version.get('status')}",
                affected_asset_id=asset_id,
                raw_data={"tool": "wpscan", "version": version},
            ))

        # Plugins
        plugins = data.get("plugins", {})
        for plugin_name, plugin_data in plugins.items():
            if plugin_data.get("vulnerabilities"):
                for vuln in plugin_data["vulnerabilities"]:
                    findings.append(RawFinding(
                        vulnerability_type="wordpress_plugin",
                        description=f"Уязвимость плагина {plugin_name}: {vuln.get('title', '')}",
                        evidence=f"CVE: {vuln.get('references', {}).get('cve', ['N/A'])[0] if vuln.get('references', {}).get('cve') else 'N/A'}",
                        affected_asset_id=asset_id,
                        raw_data={"tool": "wpscan", "plugin": plugin_name, "vulnerability": vuln},
                    ))

        # Interesting findings
        interesting = data.get("interesting_findings", [])
        for finding in interesting:
            findings.append(RawFinding(
                vulnerability_type="wordpress_finding",
                description=f"{finding.get('type', 'Finding')}: {finding.get('url', '')}",
                evidence=finding.get("detail", ""),
                affected_asset_id=asset_id,
                raw_data={"tool": "wpscan", "finding": finding},
            ))

        return findings

    # ------------------------------------------------------------------
    # whatweb — JSON
    # ------------------------------------------------------------------

    def parse_whatweb_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            # Fallback: try to parse as array
            try:
                data = json.loads(f"[{json_output.replace(chr(10), ',')}]")
            except Exception:
                return findings

        items = data if isinstance(data, list) else [data]
        for item in items:
            target = item.get("target", "")
            plugins = item.get("plugins", {})
            tech_list = []
            for plugin_name, plugin_data in plugins.items():
                version = ""
                if isinstance(plugin_data, list) and plugin_data:
                    version = str(plugin_data[0])
                elif isinstance(plugin_data, dict):
                    version = str(plugin_data.get("version", [""])[0]) if plugin_data.get("version") else ""
                tech_list.append(f"{plugin_name} {version}".strip())

            findings.append(RawFinding(
                vulnerability_type="technology_fingerprint",
                description=f"Технологии на {target}: {', '.join(tech_list[:5])}",
                evidence=f"Всего плагинов: {len(plugins)}",
                affected_asset_id=asset_id,
                raw_data={"tool": "whatweb", **item},
            ))

        return findings
