"""TechExtractor — извлечение технологий и версий из Stage 1.

Парсит результаты nmap, nuclei, httpx и других инструментов
для идентификации технологий и их версий.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime

from app.models.ai_scan_schemas import CVEInfo, TechCategory, TechnologyFingerprint
from app.models.schemas import RawFinding
from app.services.ai.llm_provider_manager import LLMProviderManager

logger = logging.getLogger(__name__)


# Паттерны для извлечения технологий из разных источников
NMAP_SERVICE_PATTERNS = [
    # Apache/2.4.41 (Ubuntu)
    (r"Apache[/\s]*([\d.]+)", "apache", TechCategory.WEB_SERVER),
    # nginx/1.18.0
    (r"nginx[/\s]*([\d.]+)", "nginx", TechCategory.WEB_SERVER),
    # Microsoft-IIS/10.0
    (r"Microsoft-IIS[/\s]*([\d.]+)", "iis", TechCategory.WEB_SERVER),
    # OpenSSH 8.2p1
    (r"OpenSSH[_\s]*([\d.p]+)", "openssh", TechCategory.OTHER),
    # MySQL 5.7.32
    (r"MySQL[/\s]*([\d.]+)", "mysql", TechCategory.DATABASE),
    # PostgreSQL 13.1
    (r"PostgreSQL[/\s]*([\d.]+)", "postgresql", TechCategory.DATABASE),
    # PHP/7.4.3
    (r"PHP[/\s]*([\d.]+)", "php", TechCategory.LANGUAGE),
    # Python/3.8.5
    (r"Python[/\s]*([\d.]+)", "python", TechCategory.LANGUAGE),
    # Node.js
    (r"Node\.?js[/\s]*([\d.]+)?", "nodejs", TechCategory.LANGUAGE),
    # Tomcat/9.0.41
    (r"Tomcat[/\s]*([\d.]+)", "tomcat", TechCategory.WEB_SERVER),
    # Redis
    (r"Redis[/\s]*([\d.]+)?", "redis", TechCategory.CACHE),
    # MongoDB
    (r"MongoDB[/\s]*([\d.]+)?", "mongodb", TechCategory.DATABASE),
]

HEADER_PATTERNS = [
    # Server: nginx/1.18.0
    (r"Server:\s*([^\r\n]+)", "server_header"),
    # X-Powered-By: PHP/7.4.3
    (r"X-Powered-By:\s*([^\r\n]+)", "powered_by"),
    # X-AspNet-Version: 4.0.30319
    (r"X-AspNet-Version:\s*([\d.]+)", "aspnet", TechCategory.FRAMEWORK),
    # X-Generator: WordPress 5.8
    (r"X-Generator:\s*([^\r\n]+)", "generator"),
]

CMS_PATTERNS = [
    (r"WordPress[/\s]*([\d.]+)?", "wordpress", TechCategory.CMS),
    (r"Drupal[/\s]*([\d.]+)?", "drupal", TechCategory.CMS),
    (r"Joomla[/\s]*([\d.]+)?", "joomla", TechCategory.CMS),
    (r"Magento[/\s]*([\d.]+)?", "magento", TechCategory.CMS),
    (r"Shopify", "shopify", TechCategory.CMS),
    (r"PrestaShop[/\s]*([\d.]+)?", "prestashop", TechCategory.CMS),
]

FRAMEWORK_PATTERNS = [
    (r"Laravel[/\s]*([\d.]+)?", "laravel", TechCategory.FRAMEWORK),
    (r"Django[/\s]*([\d.]+)?", "django", TechCategory.FRAMEWORK),
    (r"Express[/\s]*([\d.]+)?", "express", TechCategory.FRAMEWORK),
    (r"Flask[/\s]*([\d.]+)?", "flask", TechCategory.FRAMEWORK),
    (r"Spring[/\s]*([\d.]+)?", "spring", TechCategory.FRAMEWORK),
    (r"Ruby on Rails[/\s]*([\d.]+)?", "rails", TechCategory.FRAMEWORK),
    (r"ASP\.NET[/\s]*([\d.]+)?", "aspnet", TechCategory.FRAMEWORK),
    (r"Next\.js[/\s]*([\d.]+)?", "nextjs", TechCategory.FRAMEWORK),
    (r"React[/\s]*([\d.]+)?", "react", TechCategory.FRAMEWORK),
    (r"Vue\.js[/\s]*([\d.]+)?", "vuejs", TechCategory.FRAMEWORK),
    (r"Angular[/\s]*([\d.]+)?", "angular", TechCategory.FRAMEWORK),
]

WAF_PATTERNS = [
    (r"Cloudflare", "cloudflare", TechCategory.WAF),
    (r"AWS WAF", "aws_waf", TechCategory.WAF),
    (r"ModSecurity", "modsecurity", TechCategory.WAF),
    (r"Sucuri", "sucuri", TechCategory.WAF),
    (r"Imperva", "imperva", TechCategory.WAF),
    (r"Akamai", "akamai", TechCategory.CDN),
]


class TechExtractor:
    """Извлекает технологии и версии из результатов Stage 1."""

    def __init__(self, llm_manager: LLMProviderManager | None = None) -> None:
        """Инициализация экстрактора.

        Args:
            llm_manager: менеджер LLM для запроса CVE (опционально).
        """
        self._llm = llm_manager

    def extract(self, findings: list[RawFinding]) -> list[TechnologyFingerprint]:
        """Извлекает технологии из списка находок Stage 1.

        Args:
            findings: список сырых находок от инструментов.

        Returns:
            Список идентифицированных технологий.
        """
        fingerprints: dict[str, TechnologyFingerprint] = {}

        for finding in findings:
            extracted = self._extract_from_finding(finding)
            for fp in extracted:
                key = f"{fp.name}:{fp.version or 'unknown'}"
                if key not in fingerprints:
                    fingerprints[key] = fp
                else:
                    # Обновляем confidence если новый выше
                    if fp.confidence > fingerprints[key].confidence:
                        fingerprints[key] = fp

        result = list(fingerprints.values())
        logger.info("Extracted %d unique technologies from %d findings", len(result), len(findings))
        return result

    def _extract_from_finding(self, finding: RawFinding) -> list[TechnologyFingerprint]:
        """Извлекает технологии из одной находки."""
        fingerprints: list[TechnologyFingerprint] = []

        # Определяем источник по типу находки или raw_data
        source = finding.raw_data.get("tool", "unknown")
        evidence = finding.evidence or ""
        description = finding.description or ""
        raw_output = finding.raw_data.get("output", "")

        # Объединяем все текстовые данные для поиска
        search_text = f"{evidence} {description} {raw_output}"

        # === HTTPX: извлекаем технологии напрямую из raw_data ===
        if source == "httpx":
            fingerprints.extend(self._extract_httpx_technologies(finding))

        # Извлекаем из nmap-подобных данных
        if source in ("nmap", "masscan") or "port" in finding.raw_data:
            fingerprints.extend(self._extract_nmap_style(search_text, source))

        # Извлекаем из HTTP-заголовков
        if source in ("httpx", "curl") or "headers" in finding.raw_data:
            headers = finding.raw_data.get("headers", {})
            if isinstance(headers, dict):
                headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            else:
                headers_text = str(headers)
            fingerprints.extend(self._extract_from_headers(headers_text, source))

        # Извлекаем из nuclei templates
        if source == "nuclei" or "template" in finding.raw_data:
            fingerprints.extend(self._extract_nuclei_style(finding, source))

        # Общий поиск по всем паттернам
        fingerprints.extend(self._extract_general(search_text, source))

        return fingerprints

    def _extract_httpx_technologies(self, finding: RawFinding) -> list[TechnologyFingerprint]:
        """Извлекает технологии напрямую из httpx JSON output."""
        fingerprints: list[TechnologyFingerprint] = []
        
        # httpx сохраняет технологии в raw_data["technologies"]
        technologies = finding.raw_data.get("technologies", [])
        webserver = finding.raw_data.get("webserver", "")
        
        # Обрабатываем список технологий от httpx
        for tech_name in technologies:
            if not tech_name:
                continue
            
            # Определяем категорию технологии
            category = self._guess_category(tech_name.lower())
            
            # Пытаемся извлечь версию из имени (например "PHP/7.4")
            version = None
            version_match = re.search(r"[/\s]([\d.]+)", tech_name)
            if version_match:
                version = version_match.group(1)
                tech_name_clean = re.sub(r"[/\s][\d.]+.*", "", tech_name).strip()
            else:
                tech_name_clean = tech_name
            
            fingerprints.append(TechnologyFingerprint(
                id=uuid.uuid4().hex[:12],
                name=tech_name_clean.lower(),
                version=version,
                category=category,
                source="httpx",
                confidence=0.9,
                raw_evidence=f"httpx tech-detect: {tech_name}",
            ))
        
        # Обрабатываем webserver отдельно (например "nginx/1.18.0")
        if webserver:
            for pattern, name, category in NMAP_SERVICE_PATTERNS:
                match = re.search(pattern, webserver, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                    fingerprints.append(TechnologyFingerprint(
                        id=uuid.uuid4().hex[:12],
                        name=name,
                        version=version,
                        category=category,
                        source="httpx",
                        confidence=0.95,
                        raw_evidence=f"httpx webserver: {webserver}",
                    ))
                    break
        
        return fingerprints

    def _guess_category(self, tech_name: str) -> TechCategory:
        """Угадывает категорию технологии по имени."""
        # CMS
        cms_keywords = ["wordpress", "drupal", "joomla", "magento", "shopify", "prestashop", "wix", "squarespace"]
        if any(kw in tech_name for kw in cms_keywords):
            return TechCategory.CMS
        
        # Frameworks
        framework_keywords = ["laravel", "django", "flask", "express", "spring", "rails", "react", "vue", "angular", "next", "nuxt", "svelte", "bootstrap", "jquery"]
        if any(kw in tech_name for kw in framework_keywords):
            return TechCategory.FRAMEWORK
        
        # Web servers
        server_keywords = ["nginx", "apache", "iis", "tomcat", "lighttpd", "caddy"]
        if any(kw in tech_name for kw in server_keywords):
            return TechCategory.WEB_SERVER
        
        # Languages
        lang_keywords = ["php", "python", "ruby", "java", "node", "asp.net", "perl"]
        if any(kw in tech_name for kw in lang_keywords):
            return TechCategory.LANGUAGE
        
        # Databases
        db_keywords = ["mysql", "postgresql", "mongodb", "redis", "elasticsearch", "mariadb", "sqlite"]
        if any(kw in tech_name for kw in db_keywords):
            return TechCategory.DATABASE
        
        # CDN/WAF
        cdn_keywords = ["cloudflare", "akamai", "fastly", "cloudfront", "sucuri", "imperva"]
        if any(kw in tech_name for kw in cdn_keywords):
            return TechCategory.CDN
        
        # Cache
        cache_keywords = ["varnish", "memcached", "redis"]
        if any(kw in tech_name for kw in cache_keywords):
            return TechCategory.CACHE
        
        return TechCategory.OTHER

    def _extract_nmap_style(self, text: str, source: str) -> list[TechnologyFingerprint]:
        """Извлекает технологии из nmap-подобного вывода."""
        fingerprints: list[TechnologyFingerprint] = []

        for pattern, name, category in NMAP_SERVICE_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                fingerprints.append(TechnologyFingerprint(
                    id=uuid.uuid4().hex[:12],
                    name=name,
                    version=version,
                    category=category,
                    source=source,
                    confidence=0.9 if version else 0.7,
                    raw_evidence=match.group(0),
                ))

        return fingerprints

    def _extract_from_headers(self, headers_text: str, source: str) -> list[TechnologyFingerprint]:
        """Извлекает технологии из HTTP-заголовков."""
        fingerprints: list[TechnologyFingerprint] = []

        # Server header
        server_match = re.search(r"Server:\s*([^\r\n]+)", headers_text, re.IGNORECASE)
        if server_match:
            server_value = server_match.group(1)
            for pattern, name, category in NMAP_SERVICE_PATTERNS:
                match = re.search(pattern, server_value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                    fingerprints.append(TechnologyFingerprint(
                        id=uuid.uuid4().hex[:12],
                        name=name,
                        version=version,
                        category=category,
                        source=source,
                        confidence=0.95 if version else 0.8,
                        raw_evidence=server_value,
                    ))

        # X-Powered-By header
        powered_match = re.search(r"X-Powered-By:\s*([^\r\n]+)", headers_text, re.IGNORECASE)
        if powered_match:
            powered_value = powered_match.group(1)
            for pattern, name, category in NMAP_SERVICE_PATTERNS + FRAMEWORK_PATTERNS:
                match = re.search(pattern, powered_value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                    fingerprints.append(TechnologyFingerprint(
                        id=uuid.uuid4().hex[:12],
                        name=name,
                        version=version,
                        category=category,
                        source=source,
                        confidence=0.95 if version else 0.8,
                        raw_evidence=powered_value,
                    ))

        # WAF detection
        for pattern, name, category in WAF_PATTERNS:
            if re.search(pattern, headers_text, re.IGNORECASE):
                fingerprints.append(TechnologyFingerprint(
                    id=uuid.uuid4().hex[:12],
                    name=name,
                    version=None,
                    category=category,
                    source=source,
                    confidence=0.85,
                    raw_evidence=f"Detected in headers",
                ))

        return fingerprints

    def _extract_nuclei_style(self, finding: RawFinding, source: str) -> list[TechnologyFingerprint]:
        """Извлекает технологии из nuclei template matches."""
        fingerprints: list[TechnologyFingerprint] = []

        template_id = finding.raw_data.get("template", "")
        matched_at = finding.raw_data.get("matched_at", "")
        tags = finding.raw_data.get("tags", [])
        matcher_name = finding.raw_data.get("matcher_name", "")
        extracted_results = finding.raw_data.get("extracted_results", [])

        # Извлекаем технологии из тегов nuclei
        tech_tags = ["wordpress", "drupal", "joomla", "magento", "shopify", "laravel", 
                     "django", "flask", "express", "spring", "rails", "react", "vue", 
                     "angular", "nginx", "apache", "iis", "tomcat", "php", "python", 
                     "nodejs", "java", "mysql", "postgresql", "mongodb", "redis",
                     "cloudflare", "aws", "azure", "jenkins", "gitlab", "grafana",
                     "kibana", "elasticsearch", "docker", "kubernetes"]
        
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in tech_tags:
                category = self._guess_category(tag_lower)
                fingerprints.append(TechnologyFingerprint(
                    id=uuid.uuid4().hex[:12],
                    name=tag_lower,
                    version=None,
                    category=category,
                    source="nuclei",
                    confidence=0.85,
                    raw_evidence=f"Nuclei tag: {tag}",
                ))

        # Nuclei templates часто содержат имя технологии в template-id
        all_patterns = CMS_PATTERNS + FRAMEWORK_PATTERNS + NMAP_SERVICE_PATTERNS
        for pattern, name, category in all_patterns:
            if re.search(pattern, template_id, re.IGNORECASE) or re.search(pattern, finding.description, re.IGNORECASE):
                # Пытаемся извлечь версию из описания или matcher_name
                version = None
                version_match = re.search(rf"{name}[/\s]*([\d.]+)", finding.description, re.IGNORECASE)
                if not version_match and matcher_name:
                    version_match = re.search(r"([\d.]+)", matcher_name)
                if not version_match and extracted_results:
                    for result in extracted_results:
                        version_match = re.search(r"([\d.]+)", str(result))
                        if version_match:
                            break
                
                version = version_match.group(1) if version_match else None

                fingerprints.append(TechnologyFingerprint(
                    id=uuid.uuid4().hex[:12],
                    name=name,
                    version=version,
                    category=category,
                    source="nuclei",
                    confidence=0.9 if version else 0.75,
                    raw_evidence=f"Template: {template_id}",
                ))

        return fingerprints

    def _extract_general(self, text: str, source: str) -> list[TechnologyFingerprint]:
        """Общий поиск технологий по всем паттернам."""
        fingerprints: list[TechnologyFingerprint] = []
        seen: set[str] = set()

        all_patterns = CMS_PATTERNS + FRAMEWORK_PATTERNS + WAF_PATTERNS
        for pattern, name, category in all_patterns:
            if name in seen:
                continue

            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                seen.add(name)
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                fingerprints.append(TechnologyFingerprint(
                    id=uuid.uuid4().hex[:12],
                    name=name,
                    version=version,
                    category=category,
                    source=source,
                    confidence=0.7 if version else 0.5,
                    raw_evidence=match.group(0),
                ))

        return fingerprints

    async def query_cves(self, tech: TechnologyFingerprint) -> list[CVEInfo]:
        """Запрашивает известные CVE для технологии через LLM.

        Args:
            tech: идентифицированная технология.

        Returns:
            Список известных CVE.
        """
        if self._llm is None:
            return []

        if not tech.version:
            logger.debug("Skipping CVE query for %s: no version", tech.name)
            return []

        prompt = f"""Перечисли известные критические и высокие CVE для {tech.name} версии {tech.version}.
Формат ответа — JSON массив:
[
  {{"cve_id": "CVE-XXXX-XXXXX", "description": "краткое описание", "severity": "critical|high", "cvss_score": 9.8, "exploit_available": true}}
]
Если CVE неизвестны, верни пустой массив [].
Только JSON, без пояснений."""

        try:
            messages = [
                {"role": "system", "content": "Ты — эксперт по безопасности. Отвечай только валидным JSON."},
                {"role": "user", "content": prompt},
            ]
            response = self._llm.complete(messages)

            # Парсим JSON из ответа
            content = response.content.strip()
            # Убираем markdown code blocks если есть
            if content.startswith("```"):
                content = re.sub(r"```(?:json)?\n?", "", content)
                content = content.strip()

            cves_data = json.loads(content)
            cves = []
            for item in cves_data:
                cves.append(CVEInfo(
                    cve_id=item.get("cve_id", ""),
                    description=item.get("description", ""),
                    severity=item.get("severity", "unknown"),
                    cvss_score=item.get("cvss_score"),
                    exploit_available=item.get("exploit_available", False),
                ))
            return cves

        except json.JSONDecodeError as e:
            logger.warning("Failed to parse CVE response for %s: %s", tech.name, e)
            return []
        except Exception as e:
            logger.warning("CVE query failed for %s: %s", tech.name, e)
            return []

    async def enrich_with_cves(
        self, fingerprints: list[TechnologyFingerprint]
    ) -> list[TechnologyFingerprint]:
        """Обогащает fingerprints информацией о CVE.

        Args:
            fingerprints: список технологий.

        Returns:
            Список технологий с добавленными CVE.
        """
        enriched = []
        for fp in fingerprints:
            cves = await self.query_cves(fp)
            enriched_fp = TechnologyFingerprint(
                id=fp.id,
                name=fp.name,
                version=fp.version,
                category=fp.category,
                source=fp.source,
                confidence=fp.confidence,
                raw_evidence=fp.raw_evidence,
                known_cves=cves,
            )
            enriched.append(enriched_fp)

        return enriched
