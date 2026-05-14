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
    # New tools
    "assetfinder": "parse_assetfinder_text",
    "katana": "parse_katana_json",
    "dnsx": "parse_dnsx_json",
    "testssl": "parse_testssl_json",
    "arjun": "parse_arjun_json",
    "paramspider": "parse_paramspider_text",
    "trufflehog": "parse_trufflehog_json",
    "gitleaks": "parse_gitleaks_json",
    "corsy": "parse_corsy_json",
    # CMS scanners
    "joomscan": "parse_joomscan_text",
    "droopescan": "parse_droopescan_json",
    # Injection tools
    "commix": "parse_commix_text",
    "tplmap": "parse_tplmap_text",
    # JWT & Auth
    "jwt_tool": "parse_jwt_tool_text",
    # HTTP Smuggling
    "smuggler": "parse_smuggler_text",
    # CORS
    "corscanner": "parse_corscanner_json",
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

                description = f"Открытый порт {port_id}/{protocol}: {service_name}"
                if product:
                    description += f" ({product}"
                    if service_version:
                        description += f" {service_version}"
                    description += ")"

                findings.append(RawFinding(
                    vulnerability_type="open_port",
                    description=description,
                    evidence=f"Хост: {host_addr}, Порт: {port_id}/{protocol}, Сервис: {service_name}",
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

    # Словарь переводов для nuclei шаблонов
    NUCLEI_TRANSLATIONS = {
        # CSP
        "weak-csp-detect": ("Слабая политика CSP", "Обнаружена небезопасная конфигурация Content-Security-Policy с разрешёнными небезопасными директивами"),
        "csp-header-missing": ("Отсутствует заголовок CSP", "Заголовок Content-Security-Policy не настроен, что позволяет XSS-атаки"),
        "content-security-policy": ("Проблема CSP", "Обнаружена проблема с политикой безопасности контента"),
        
        # Headers
        "missing-x-frame-options": ("Отсутствует X-Frame-Options", "Сайт уязвим к clickjacking атакам"),
        "x-frame-options": ("Проблема X-Frame-Options", "Некорректная настройка защиты от clickjacking"),
        "missing-hsts": ("Отсутствует HSTS", "Не настроен HTTP Strict Transport Security"),
        "strict-transport-security": ("Проблема HSTS", "Некорректная настройка HSTS"),
        "x-content-type-options": ("Отсутствует X-Content-Type-Options", "Возможны MIME-sniffing атаки"),
        "x-xss-protection": ("Отсутствует X-XSS-Protection", "Не включена встроенная защита браузера от XSS"),
        "permissions-policy": ("Отсутствует Permissions-Policy", "Не ограничены разрешения браузера"),
        "referrer-policy": ("Отсутствует Referrer-Policy", "Возможна утечка данных через Referer"),
        
        # SSL/TLS
        "ssl-issuer": ("Информация о SSL сертификате", "Получена информация об издателе сертификата"),
        "ssl-dns-names": ("DNS имена в сертификате", "Обнаружены альтернативные имена в SSL сертификате"),
        "expired-ssl": ("Истёкший SSL сертификат", "SSL сертификат истёк или скоро истечёт"),
        "self-signed-ssl": ("Самоподписанный сертификат", "Используется самоподписанный SSL сертификат"),
        "mismatched-ssl": ("Несоответствие SSL", "Имя домена не соответствует сертификату"),
        "weak-cipher-suites": ("Слабые шифры", "Сервер поддерживает устаревшие криптографические алгоритмы"),
        "tls-version": ("Устаревший TLS", "Поддерживаются устаревшие версии TLS"),
        
        # Technologies
        "tech-detect": ("Обнаружена технология", "Определён используемый фреймворк или CMS"),
        "waf-detect": ("Обнаружен WAF", "Определён Web Application Firewall"),
        "wordpress-detect": ("Обнаружен WordPress", "Сайт работает на WordPress CMS"),
        "nginx-version": ("Версия Nginx", "Раскрыта версия веб-сервера Nginx"),
        "apache-version": ("Версия Apache", "Раскрыта версия веб-сервера Apache"),
        "php-version": ("Версия PHP", "Раскрыта версия PHP"),
        
        # Exposures
        "git-config": ("Доступен .git", "Директория .git доступна извне"),
        "git-config-exposure": ("Утечка .git/config", "Файл конфигурации git доступен"),
        "env-file": ("Доступен .env файл", "Файл переменных окружения доступен"),
        "ds-store": ("Доступен .DS_Store", "Файл macOS с метаданными доступен"),
        "backup-file": ("Найден файл бэкапа", "Обнаружен файл резервной копии"),
        "phpinfo": ("Доступен phpinfo()", "Страница phpinfo раскрывает конфигурацию"),
        "debug-enabled": ("Включён режим отладки", "Debug mode раскрывает внутреннюю информацию"),
        "directory-listing": ("Листинг директорий", "Включён просмотр содержимого директорий"),
        "robots-txt": ("Файл robots.txt", "Обнаружен файл robots.txt"),
        "sitemap": ("Файл sitemap.xml", "Обнаружен файл карты сайта"),
        
        # Vulnerabilities
        "xss": ("XSS уязвимость", "Обнаружена возможность внедрения скриптов"),
        "sqli": ("SQL инъекция", "Обнаружена возможность SQL инъекции"),
        "lfi": ("Local File Inclusion", "Возможно чтение локальных файлов"),
        "rfi": ("Remote File Inclusion", "Возможно подключение удалённых файлов"),
        "ssrf": ("SSRF уязвимость", "Возможны запросы от имени сервера"),
        "open-redirect": ("Открытый редирект", "Возможно перенаправление на внешний сайт"),
        "cors-misconfig": ("Неправильный CORS", "Небезопасная конфигурация CORS"),
        "crlf-injection": ("CRLF инъекция", "Возможно внедрение заголовков"),
        "host-header-injection": ("Host Header Injection", "Уязвимость в обработке заголовка Host"),
        
        # Default credentials
        "default-login": ("Стандартные учётные данные", "Возможен вход со стандартным паролем"),
        "admin-panel": ("Административная панель", "Обнаружена панель администратора"),
        
        # Info
        "http-missing-security-headers": ("Отсутствуют заголовки безопасности", "Не настроены HTTP заголовки безопасности"),
        "options-method": ("Метод OPTIONS", "Сервер отвечает на OPTIONS запросы"),
        "trace-method": ("Метод TRACE включён", "Метод TRACE может использоваться для XST атак"),
    }

    def _translate_nuclei(self, template_id: str, name: str, description: str, severity: str) -> tuple[str, str]:
        """Переводит nuclei находку на русский."""
        # Ищем точное совпадение
        if template_id in self.NUCLEI_TRANSLATIONS:
            ru_name, ru_desc = self.NUCLEI_TRANSLATIONS[template_id]
            return ru_name, ru_desc
        
        # Ищем частичное совпадение
        template_lower = template_id.lower()
        for key, (ru_name, ru_desc) in self.NUCLEI_TRANSLATIONS.items():
            if key in template_lower or template_lower in key:
                return ru_name, ru_desc
        
        # Переводим severity
        severity_ru = {
            "critical": "КРИТИЧЕСКИЙ",
            "high": "ВЫСОКИЙ", 
            "medium": "СРЕДНИЙ",
            "low": "НИЗКИЙ",
            "info": "ИНФО",
            "unknown": "НЕИЗВЕСТНО",
        }.get(severity.lower(), severity.upper())
        
        # Возвращаем оригинал с переведённым severity
        return f"[{severity_ru}] {name}", description or "Обнаружено nuclei шаблоном"

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
            
            # Извлекаем теги технологий из nuclei
            tags = item.get("info", {}).get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            
            # Извлекаем matcher-name (часто содержит версию)
            matcher_name = item.get("matcher-name", "")
            extracted_results = item.get("extracted-results", [])

            # Переводим на русский
            ru_name, ru_desc = self._translate_nuclei(template_id, name, description, severity)

            findings.append(RawFinding(
                vulnerability_type=f"nuclei_{template_id}",
                description=f"{ru_name}: {ru_desc}" if ru_desc else ru_name,
                evidence=f"Обнаружено на: {matched_at}",
                affected_asset_id=asset_id,
                raw_data={
                    "tool": "nuclei",
                    "template": template_id,
                    "severity": severity,
                    "matched_at": matched_at,
                    "name": name,
                    "tags": tags,  # Теги для извлечения технологий
                    "matcher_name": matcher_name,
                    "extracted_results": extracted_results,
                    **{k: v for k, v in item.items() if k not in ("template-id", "templateID", "info", "matched-at", "host", "matcher-name", "extracted-results")},
                },
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
            
            # Формируем детальное описание технологий
            tech_details = []
            if webserver:
                tech_details.append(f"Сервер: {webserver}")
            if tech:
                tech_details.append(f"Технологии: {', '.join(tech)}")
            
            tech_str = "; ".join(tech_details) if tech_details else "N/A"

            findings.append(RawFinding(
                vulnerability_type="host_probe",
                description=f"Живой хост: {url} (статус {status_code})",
                evidence=f"Заголовок: {title or 'N/A'}, {tech_str}",
                affected_asset_id=asset_id,
                raw_data={
                    "tool": "httpx",
                    "url": url,
                    "status_code": status_code,
                    "title": title,
                    "technologies": tech,  # Сохраняем как список для tech_extractor
                    "webserver": webserver,
                    **{k: v for k, v in item.items() if k not in ("url", "status_code", "title", "technologies", "webserver")},
                },
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


    # ==================================================================
    # NEW DEEP SCANNING TOOLS PARSERS
    # ==================================================================

    # ------------------------------------------------------------------
    # assetfinder — text (subdomains)
    # ------------------------------------------------------------------

    def parse_assetfinder_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        subdomains: set[str] = set()
        for line in text_output.strip().splitlines():
            subdomain = line.strip()
            if subdomain and subdomain not in subdomains:
                subdomains.add(subdomain)
                findings.append(RawFinding(
                    vulnerability_type="subdomain_discovery",
                    description=f"Обнаружен поддомен: {subdomain}",
                    evidence=f"Источник: assetfinder",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "assetfinder", "subdomain": subdomain},
                ))
        return findings

    # ------------------------------------------------------------------
    # katana — JSONL (crawled URLs)
    # ------------------------------------------------------------------

    def parse_katana_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        urls: set[str] = set()
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = item.get("request", {}).get("endpoint", "") or item.get("url", "")
            if url and url not in urls:
                urls.add(url)
                findings.append(RawFinding(
                    vulnerability_type="crawled_url",
                    description=f"Обнаружен URL при краулинге: {url}",
                    evidence=f"Метод: {item.get('request', {}).get('method', 'GET')}",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "katana", **item},
                ))
        return findings

    # ------------------------------------------------------------------
    # dnsx — JSONL (DNS records)
    # ------------------------------------------------------------------

    def parse_dnsx_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
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
            a_records = item.get("a", [])
            aaaa_records = item.get("aaaa", [])
            cname_records = item.get("cname", [])
            mx_records = item.get("mx", [])
            txt_records = item.get("txt", [])
            
            records_info = []
            if a_records:
                records_info.append(f"A: {', '.join(a_records)}")
            if aaaa_records:
                records_info.append(f"AAAA: {', '.join(aaaa_records)}")
            if cname_records:
                records_info.append(f"CNAME: {', '.join(cname_records)}")
            if mx_records:
                records_info.append(f"MX: {', '.join(mx_records)}")
            if txt_records:
                records_info.append(f"TXT: {', '.join(txt_records[:3])}")
            
            if records_info:
                findings.append(RawFinding(
                    vulnerability_type="dns_records",
                    description=f"DNS записи для {host}",
                    evidence="; ".join(records_info),
                    affected_asset_id=asset_id,
                    raw_data={"tool": "dnsx", **item},
                ))
        return findings

    # ------------------------------------------------------------------
    # testssl — JSON (SSL/TLS issues)
    # ------------------------------------------------------------------

    def parse_testssl_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings

        # testssl output is usually a list of findings
        items = data if isinstance(data, list) else data.get("scanResult", [])
        
        for item in items:
            severity = item.get("severity", "INFO")
            finding_id = item.get("id", "unknown")
            finding_text = item.get("finding", "")
            
            # Skip informational items
            if severity.upper() in ["OK", "INFO"] and "vulnerable" not in finding_text.lower():
                continue
            
            vuln_type = "ssl_tls_issue"
            if "certificate" in finding_id.lower():
                vuln_type = "ssl_certificate_issue"
            elif "cipher" in finding_id.lower():
                vuln_type = "weak_cipher"
            elif "protocol" in finding_id.lower():
                vuln_type = "insecure_protocol"
            
            findings.append(RawFinding(
                vulnerability_type=vuln_type,
                description=f"[{severity}] {finding_id}: {finding_text}",
                evidence=f"ID: {finding_id}",
                affected_asset_id=asset_id,
                raw_data={"tool": "testssl", **item},
            ))
        return findings

    # ------------------------------------------------------------------
    # arjun — JSON (hidden parameters)
    # ------------------------------------------------------------------

    def parse_arjun_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings

        # arjun output: {"url": {"params": ["param1", "param2"]}}
        if isinstance(data, dict):
            for url, params_data in data.items():
                params = params_data.get("params", []) if isinstance(params_data, dict) else params_data
                if params:
                    findings.append(RawFinding(
                        vulnerability_type="hidden_parameter",
                        description=f"Обнаружены скрытые параметры на {url}",
                        evidence=f"Параметры: {', '.join(params)}",
                        affected_asset_id=asset_id,
                        raw_data={"tool": "arjun", "url": url, "params": params},
                    ))
        return findings

    # ------------------------------------------------------------------
    # paramspider — text (URLs with parameters)
    # ------------------------------------------------------------------

    def parse_paramspider_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        urls: set[str] = set()
        for line in text_output.strip().splitlines():
            url = line.strip()
            if url and "?" in url and url not in urls:
                urls.add(url)
                # Extract parameters
                params_part = url.split("?")[1] if "?" in url else ""
                params = [p.split("=")[0] for p in params_part.split("&") if "=" in p]
                findings.append(RawFinding(
                    vulnerability_type="parameterized_url",
                    description=f"URL с параметрами: {url[:100]}...",
                    evidence=f"Параметры: {', '.join(params)}",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "paramspider", "url": url, "params": params},
                ))
        return findings

    # ------------------------------------------------------------------
    # trufflehog — JSONL (secrets)
    # ------------------------------------------------------------------

    def parse_trufflehog_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in json_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            detector_name = item.get("DetectorName", item.get("detectorName", "unknown"))
            raw_value = item.get("Raw", item.get("raw", ""))[:50] + "..."  # Truncate secret
            source_metadata = item.get("SourceMetadata", {})
            file_path = source_metadata.get("Data", {}).get("Filesystem", {}).get("file", "unknown")
            
            findings.append(RawFinding(
                vulnerability_type="exposed_secret",
                description=f"Обнаружен секрет типа {detector_name}",
                evidence=f"Файл: {file_path}, Значение: {raw_value}",
                affected_asset_id=asset_id,
                raw_data={"tool": "trufflehog", "detector": detector_name, "file": file_path},
            ))
        return findings

    # ------------------------------------------------------------------
    # gitleaks — JSON (git secrets)
    # ------------------------------------------------------------------

    def parse_gitleaks_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings

        items = data if isinstance(data, list) else [data]
        for item in items:
            rule_id = item.get("RuleID", item.get("ruleID", "unknown"))
            file_path = item.get("File", item.get("file", "unknown"))
            line_number = item.get("StartLine", item.get("line", 0))
            secret = item.get("Secret", item.get("secret", ""))[:30] + "..."  # Truncate
            
            findings.append(RawFinding(
                vulnerability_type="git_secret_leak",
                description=f"Утечка секрета в git: {rule_id}",
                evidence=f"Файл: {file_path}:{line_number}, Секрет: {secret}",
                affected_asset_id=asset_id,
                raw_data={"tool": "gitleaks", "rule": rule_id, "file": file_path, "line": line_number},
            ))
        return findings

    # ------------------------------------------------------------------
    # corsy — JSON (CORS misconfigurations)
    # ------------------------------------------------------------------

    def parse_corsy_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings

        # corsy output varies, handle both dict and list
        items = data if isinstance(data, list) else [data] if data else []
        
        for item in items:
            url = item.get("url", "unknown")
            vuln_type = item.get("type", item.get("class", "CORS misconfiguration"))
            description = item.get("description", f"CORS уязвимость: {vuln_type}")
            
            findings.append(RawFinding(
                vulnerability_type="cors_misconfiguration",
                description=f"CORS уязвимость на {url}: {vuln_type}",
                evidence=description,
                affected_asset_id=asset_id,
                raw_data={"tool": "corsy", **item},
            ))
        return findings

    # ==================================================================
    # CMS SCANNERS PARSERS
    # ==================================================================

    # ------------------------------------------------------------------
    # joomscan — text (Joomla vulnerabilities)
    # ------------------------------------------------------------------

    def parse_joomscan_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        
        # Parse Joomla version
        version_match = re.search(r"Joomla\s+(\d+\.\d+(?:\.\d+)?)", text_output, re.IGNORECASE)
        if version_match:
            version = version_match.group(1)
            findings.append(RawFinding(
                vulnerability_type="cms_version",
                description=f"Обнаружена версия Joomla: {version}",
                evidence=f"Версия: {version}",
                affected_asset_id=asset_id,
                raw_data={"tool": "joomscan", "cms": "joomla", "version": version},
            ))
        
        # Parse vulnerabilities
        vuln_pattern = re.compile(r"\[!\]\s*(.+?)(?:\n|$)", re.MULTILINE)
        for match in vuln_pattern.finditer(text_output):
            vuln_text = match.group(1).strip()
            if vuln_text and "vulnerability" in vuln_text.lower():
                findings.append(RawFinding(
                    vulnerability_type="joomla_vulnerability",
                    description=f"Joomla уязвимость: {vuln_text}",
                    evidence=vuln_text,
                    affected_asset_id=asset_id,
                    raw_data={"tool": "joomscan", "finding": vuln_text},
                ))
        
        # Parse exposed directories/files
        exposed_pattern = re.compile(r"(?:admin|backup|config|debug|install|tmp|log)[^\s]*", re.IGNORECASE)
        for match in exposed_pattern.finditer(text_output):
            path = match.group(0)
            findings.append(RawFinding(
                vulnerability_type="exposed_path",
                description=f"Обнаружен путь Joomla: {path}",
                evidence=f"Путь: {path}",
                affected_asset_id=asset_id,
                raw_data={"tool": "joomscan", "path": path},
            ))
        
        return findings

    # ------------------------------------------------------------------
    # droopescan — JSON (CMS vulnerabilities)
    # ------------------------------------------------------------------

    def parse_droopescan_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            # Fallback to text parsing
            return self._parse_droopescan_text(json_output, asset_id)

        cms_type = data.get("cms", "unknown")
        version = data.get("version", {})
        plugins = data.get("plugins", {})
        themes = data.get("themes", {})
        interesting = data.get("interesting_urls", [])
        
        # Version info
        if version:
            ver_str = version.get("version", "unknown")
            findings.append(RawFinding(
                vulnerability_type="cms_version",
                description=f"Обнаружена версия {cms_type}: {ver_str}",
                evidence=f"CMS: {cms_type}, Версия: {ver_str}",
                affected_asset_id=asset_id,
                raw_data={"tool": "droopescan", "cms": cms_type, "version": ver_str},
            ))
        
        # Plugins
        if plugins:
            for plugin_name, plugin_data in plugins.items():
                findings.append(RawFinding(
                    vulnerability_type="cms_plugin",
                    description=f"Обнаружен плагин {cms_type}: {plugin_name}",
                    evidence=f"Плагин: {plugin_name}",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "droopescan", "plugin": plugin_name, "data": plugin_data},
                ))
        
        # Interesting URLs
        for url_info in interesting:
            url = url_info if isinstance(url_info, str) else url_info.get("url", "")
            if url:
                findings.append(RawFinding(
                    vulnerability_type="interesting_url",
                    description=f"Интересный URL {cms_type}: {url}",
                    evidence=f"URL: {url}",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "droopescan", "url": url},
                ))
        
        return findings

    def _parse_droopescan_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        """Fallback parser for droopescan text output."""
        findings: list[RawFinding] = []
        for line in text_output.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                findings.append(RawFinding(
                    vulnerability_type="cms_finding",
                    description=f"Droopescan: {line}",
                    evidence=line,
                    affected_asset_id=asset_id,
                    raw_data={"tool": "droopescan", "raw_line": line},
                ))
        return findings

    # ==================================================================
    # INJECTION TOOLS PARSERS
    # ==================================================================

    # ------------------------------------------------------------------
    # commix — text (Command injection)
    # ------------------------------------------------------------------

    def parse_commix_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        
        # Parse vulnerable parameters
        vuln_pattern = re.compile(
            r"(?:parameter|param)\s*['\"]?(\w+)['\"]?\s*(?:is|appears to be)\s*(?:vulnerable|injectable)",
            re.IGNORECASE
        )
        for match in vuln_pattern.finditer(text_output):
            param = match.group(1)
            findings.append(RawFinding(
                vulnerability_type="command_injection",
                description=f"Command Injection в параметре: {param}",
                evidence=f"Параметр: {param}",
                affected_asset_id=asset_id,
                raw_data={"tool": "commix", "parameter": param},
            ))
        
        # Parse injection techniques
        technique_pattern = re.compile(
            r"(?:classic|eval-based|time-based|file-based)\s+(?:command\s+)?injection",
            re.IGNORECASE
        )
        for match in technique_pattern.finditer(text_output):
            technique = match.group(0)
            findings.append(RawFinding(
                vulnerability_type="command_injection",
                description=f"Обнаружена техника: {technique}",
                evidence=technique,
                affected_asset_id=asset_id,
                raw_data={"tool": "commix", "technique": technique},
            ))
        
        # Generic vulnerable detection
        if re.search(r"vulnerable|injection\s+point", text_output, re.IGNORECASE) and not findings:
            findings.append(RawFinding(
                vulnerability_type="command_injection",
                description="Потенциальная Command Injection обнаружена",
                evidence=text_output[:500],
                affected_asset_id=asset_id,
                raw_data={"tool": "commix", "raw_output": text_output[:2000]},
            ))
        
        return findings

    # ------------------------------------------------------------------
    # tplmap — text (SSTI)
    # ------------------------------------------------------------------

    def parse_tplmap_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        
        # Parse template engine detection
        engine_pattern = re.compile(
            r"(?:Smarty|Mako|Jinja2|Twig|Freemarker|Velocity|Jade|Pug|ERB|Slim|Haml|Dust)\s*(?:confirmed|detected|identified)",
            re.IGNORECASE
        )
        for match in engine_pattern.finditer(text_output):
            engine = match.group(0)
            findings.append(RawFinding(
                vulnerability_type="ssti",
                description=f"SSTI: {engine}",
                evidence=engine,
                affected_asset_id=asset_id,
                raw_data={"tool": "tplmap", "engine": engine},
            ))
        
        # Parse vulnerable parameters
        param_pattern = re.compile(
            r"(?:parameter|param)\s*['\"]?(\w+)['\"]?\s*(?:is|appears)\s*(?:vulnerable|injectable)",
            re.IGNORECASE
        )
        for match in param_pattern.finditer(text_output):
            param = match.group(1)
            findings.append(RawFinding(
                vulnerability_type="ssti",
                description=f"SSTI в параметре: {param}",
                evidence=f"Параметр: {param}",
                affected_asset_id=asset_id,
                raw_data={"tool": "tplmap", "parameter": param},
            ))
        
        # Generic SSTI detection
        if re.search(r"server.side\s+template\s+injection|ssti", text_output, re.IGNORECASE) and not findings:
            findings.append(RawFinding(
                vulnerability_type="ssti",
                description="Потенциальная SSTI уязвимость обнаружена",
                evidence=text_output[:500],
                affected_asset_id=asset_id,
                raw_data={"tool": "tplmap", "raw_output": text_output[:2000]},
            ))
        
        return findings

    # ==================================================================
    # JWT & AUTH PARSERS
    # ==================================================================

    # ------------------------------------------------------------------
    # jwt_tool — text (JWT vulnerabilities)
    # ------------------------------------------------------------------

    def parse_jwt_tool_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        
        # Parse algorithm vulnerabilities
        alg_pattern = re.compile(
            r"(?:alg|algorithm)\s*[:\s]+['\"]?(none|HS256|RS256|ES256)['\"]?\s*(?:accepted|vulnerable|weak)",
            re.IGNORECASE
        )
        for match in alg_pattern.finditer(text_output):
            alg = match.group(1)
            findings.append(RawFinding(
                vulnerability_type="jwt_vulnerability",
                description=f"JWT уязвимость алгоритма: {alg}",
                evidence=f"Алгоритм: {alg}",
                affected_asset_id=asset_id,
                raw_data={"tool": "jwt_tool", "algorithm": alg},
            ))
        
        # Parse signature bypass
        if re.search(r"signature\s*(?:bypass|not\s+verified|ignored)", text_output, re.IGNORECASE):
            findings.append(RawFinding(
                vulnerability_type="jwt_vulnerability",
                description="JWT: Обход проверки подписи",
                evidence="Signature bypass detected",
                affected_asset_id=asset_id,
                raw_data={"tool": "jwt_tool", "issue": "signature_bypass"},
            ))
        
        # Parse key confusion
        if re.search(r"key\s*confusion|algorithm\s*confusion", text_output, re.IGNORECASE):
            findings.append(RawFinding(
                vulnerability_type="jwt_vulnerability",
                description="JWT: Algorithm Confusion Attack",
                evidence="Key/Algorithm confusion detected",
                affected_asset_id=asset_id,
                raw_data={"tool": "jwt_tool", "issue": "algorithm_confusion"},
            ))
        
        # Parse weak secret
        if re.search(r"weak\s*secret|secret\s*found|cracked", text_output, re.IGNORECASE):
            findings.append(RawFinding(
                vulnerability_type="jwt_vulnerability",
                description="JWT: Слабый секретный ключ",
                evidence="Weak secret detected",
                affected_asset_id=asset_id,
                raw_data={"tool": "jwt_tool", "issue": "weak_secret"},
            ))
        
        return findings

    # ==================================================================
    # HTTP SMUGGLING PARSERS
    # ==================================================================

    # ------------------------------------------------------------------
    # smuggler — text (HTTP Request Smuggling)
    # ------------------------------------------------------------------

    def parse_smuggler_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        
        # Parse smuggling techniques
        techniques = [
            ("CL.TE", "Content-Length / Transfer-Encoding"),
            ("TE.CL", "Transfer-Encoding / Content-Length"),
            ("TE.TE", "Transfer-Encoding obfuscation"),
            ("CL.0", "Content-Length: 0"),
        ]
        
        for tech_code, tech_name in techniques:
            if re.search(rf"{tech_code}.*(?:vulnerable|detected|found)", text_output, re.IGNORECASE):
                findings.append(RawFinding(
                    vulnerability_type="http_smuggling",
                    description=f"HTTP Request Smuggling: {tech_name}",
                    evidence=f"Техника: {tech_code}",
                    affected_asset_id=asset_id,
                    raw_data={"tool": "smuggler", "technique": tech_code},
                ))
        
        # Generic smuggling detection
        if re.search(r"smuggl(?:ing|ed)|desync", text_output, re.IGNORECASE) and not findings:
            findings.append(RawFinding(
                vulnerability_type="http_smuggling",
                description="Потенциальная HTTP Request Smuggling уязвимость",
                evidence=text_output[:500],
                affected_asset_id=asset_id,
                raw_data={"tool": "smuggler", "raw_output": text_output[:2000]},
            ))
        
        return findings

    # ==================================================================
    # CORS PARSERS
    # ==================================================================

    # ------------------------------------------------------------------
    # corscanner — JSON (CORS misconfigurations)
    # ------------------------------------------------------------------

    def parse_corscanner_json(self, json_output: str, asset_id: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            # Fallback to text parsing
            return self._parse_corscanner_text(json_output, asset_id)

        items = data if isinstance(data, list) else [data] if data else []
        
        for item in items:
            url = item.get("url", "unknown")
            vuln_type = item.get("type", item.get("vulnerability", "CORS misconfiguration"))
            origin = item.get("origin", "")
            credentials = item.get("credentials", False)
            
            severity = "high" if credentials else "medium"
            
            findings.append(RawFinding(
                vulnerability_type="cors_misconfiguration",
                description=f"CORS уязвимость на {url}: {vuln_type}",
                evidence=f"Origin: {origin}, Credentials: {credentials}",
                affected_asset_id=asset_id,
                raw_data={"tool": "corscanner", "severity": severity, **item},
            ))
        
        return findings

    def _parse_corscanner_text(self, text_output: str, asset_id: str) -> list[RawFinding]:
        """Fallback parser for CORScanner text output."""
        findings: list[RawFinding] = []
        
        # Parse CORS issues from text
        cors_pattern = re.compile(
            r"(?:CORS|Access-Control).*(?:vulnerable|misconfigured|wildcard|\*)",
            re.IGNORECASE
        )
        for match in cors_pattern.finditer(text_output):
            finding_text = match.group(0)
            findings.append(RawFinding(
                vulnerability_type="cors_misconfiguration",
                description=f"CORS проблема: {finding_text}",
                evidence=finding_text,
                affected_asset_id=asset_id,
                raw_data={"tool": "corscanner", "raw_line": finding_text},
            ))
        
        return findings
