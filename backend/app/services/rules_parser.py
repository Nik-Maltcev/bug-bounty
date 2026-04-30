"""Парсер правил программы bug bounty.

Извлекает структурированные данные (активы, правила, вознаграждения,
требования к раскрытию) из текстового описания или URL программы.
"""

import re
import uuid
from datetime import UTC, datetime

import httpx

from app.core.exceptions import ParseError
from app.models.schemas import (
    Asset,
    AssetType,
    ParsedProgram,
    ProgramRule,
    ProgramSource,
    RewardTier,
    SeverityLevel,
)

# Mapping строковых типов активов к AssetType
_ASSET_TYPE_MAP: dict[str, AssetType] = {
    "web": AssetType.WEB_APPLICATION,
    "web_application": AssetType.WEB_APPLICATION,
    "webapp": AssetType.WEB_APPLICATION,
}

# Mapping строковых уровней серьёзности к SeverityLevel
_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "informational": SeverityLevel.INFORMATIONAL,
    "info": SeverityLevel.INFORMATIONAL,
}

# Reverse mapping: AssetType → короткое строковое представление для format_rules
_ASSET_TYPE_TO_STR: dict[AssetType, str] = {
    AssetType.WEB_APPLICATION: "web",
}


def _gen_id() -> str:
    """Генерирует UUID для идентификаторов."""
    return str(uuid.uuid4())


class RulesParser:
    """Парсер правил программы bug bounty."""

    async def parse(self, source: ProgramSource) -> ParsedProgram:
        """Извлекает структурированные данные из описания программы.

        Args:
            source: URL или текст описания программы.

        Returns:
            ParsedProgram с правилами, scope и ограничениями.

        Raises:
            ParseError: если не удалось извлечь данные.
        """
        text = await self._resolve_source(source)
        return self._parse_text(text)

    def format_rules(self, program: ParsedProgram) -> str:
        """Форматирует правила обратно в текстовое представление.

        Args:
            program: структурированные данные программы.

        Returns:
            Текстовое представление правил для верификации.
        """
        lines: list[str] = []

        # Заголовок
        lines.append(f"# Program: {program.name}")
        lines.append(f"Platform: {program.platform}")
        lines.append("")

        # Активы
        if program.assets:
            lines.append("## Assets")
            for asset in program.assets:
                type_str = _ASSET_TYPE_TO_STR.get(asset.asset_type, "web")
                entry = f"- [{type_str}] {asset.target} ({asset.name})"
                if not asset.in_scope:
                    entry += " (out of scope)"
                lines.append(entry)
            lines.append("")

        # Правила
        if program.rules:
            lines.append("## Rules")
            for rule in program.rules:
                tag = "ALLOWED" if rule.is_allowed else "FORBIDDEN"
                lines.append(f"- [{tag}] {rule.description}")
            lines.append("")

        # Вознаграждения
        if program.reward_tiers:
            lines.append("## Rewards")
            for tier in program.reward_tiers:
                min_val = int(tier.min_reward) if tier.min_reward == int(tier.min_reward) else tier.min_reward
                max_val = int(tier.max_reward) if tier.max_reward == int(tier.max_reward) else tier.max_reward
                entry = f"- {tier.severity.value}: ${min_val}-${max_val}"
                if tier.currency != "USD":
                    entry += f" {tier.currency}"
                lines.append(entry)
            lines.append("")

        # Требования к раскрытию
        if program.disclosure_requirements:
            lines.append("## Disclosure")
            for line in program.disclosure_requirements.splitlines():
                stripped = line.strip()
                if stripped:
                    lines.append(f"- {stripped}")
            lines.append("")

        return "\n".join(lines) + "\n"

    def reparse(self, text: str) -> ParsedProgram:
        """Повторный парсинг из текстового представления.

        Используется для верификации round-trip свойства.

        Args:
            text: текстовое представление программы.

        Returns:
            ParsedProgram с правилами, scope и ограничениями.
        """
        return self._parse_text(text)

    # ------------------------------------------------------------------
    # Получение текста из источника
    # ------------------------------------------------------------------

    async def _resolve_source(self, source: ProgramSource) -> str:
        """Получает текст программы из URL или напрямую."""
        if source.text:
            return source.text

        if source.url:
            return await self._fetch_url(source.url)

        raise ParseError(
            source="(empty)",
            reason="Необходимо указать URL или текст программы",
        )

    async def _fetch_url(self, url: str) -> str:
        """Загружает содержимое страницы по URL."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                return response.text
        except httpx.HTTPError as exc:
            raise ParseError(source=url, reason=f"Ошибка загрузки: {exc}") from exc

    # ------------------------------------------------------------------
    # Основной парсинг текста
    # ------------------------------------------------------------------

    def _parse_text(self, text: str) -> ParsedProgram:
        """Парсит текст программы и возвращает ParsedProgram."""
        stripped = text.strip()
        if not stripped:
            raise ParseError(source="(text)", reason="Пустой текст программы")

        name = self._extract_program_name(stripped)
        platform = self._extract_platform(stripped)
        sections = self._split_sections(stripped)

        assets = self._parse_assets(sections.get("assets", ""))
        rules = self._parse_rules(sections.get("rules", ""))
        reward_tiers = self._parse_rewards(sections.get("rewards", ""))
        disclosure = self._parse_disclosure(sections.get("disclosure", ""))

        return ParsedProgram(
            id=_gen_id(),
            name=name,
            platform=platform,
            assets=assets,
            rules=rules,
            reward_tiers=reward_tiers,
            disclosure_requirements=disclosure,
            raw_text=text,
            created_at=datetime.now(UTC),
        )

    # ------------------------------------------------------------------
    # Извлечение метаданных
    # ------------------------------------------------------------------

    def _extract_program_name(self, text: str) -> str:
        """Извлекает имя программы из заголовка."""
        # Поддерживаем: "# Program: Name" и "Program: Name"
        match = re.search(r"^#{0,3}\s*Program:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        # Fallback: первая строка, начинающаяся с #
        match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return "Unknown Program"

    def _extract_platform(self, text: str) -> str:
        """Извлекает платформу из текста."""
        match = re.search(r"^#{0,3}\s*Platform:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip().lower()
        # Автоопределение по ключевым словам
        lower = text.lower()
        for platform in ("hackerone", "bugcrowd", "immunefi"):
            if platform in lower:
                return platform
        return "custom"

    # ------------------------------------------------------------------
    # Разбиение на секции
    # ------------------------------------------------------------------

    def _split_sections(self, text: str) -> dict[str, str]:
        """Разбивает текст на именованные секции по заголовкам ##."""
        sections: dict[str, str] = {}
        # Ищем заголовки вида "## Assets", "## Rules" и т.д.
        pattern = re.compile(r"^#{1,3}\s+(\w+)", re.MULTILINE)
        matches = list(pattern.finditer(text))

        for i, m in enumerate(matches):
            key = m.group(1).lower()
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            sections[key] = text[start:end].strip()

        return sections

    # ------------------------------------------------------------------
    # Парсинг активов
    # ------------------------------------------------------------------

    def _parse_assets(self, section: str) -> list[Asset]:
        """Парсит секцию активов.

        Формат строки: - [type] target (name)
        Опционально: (out of scope) в конце.
        """
        assets: list[Asset] = []
        if not section:
            return assets

        # Паттерн: - [type] target (name) (out of scope)?
        pattern = re.compile(
            r"^-\s+\[(\w+)\]\s+(\S+)"  # тип и target
            r"(?:\s+\(([^)]+)\))?"       # опциональное имя в скобках
            r"(.*)",                      # остаток строки
            re.MULTILINE,
        )

        for match in pattern.finditer(section):
            raw_type = match.group(1).lower()
            target = match.group(2).strip()
            name_part = match.group(3)
            remainder = match.group(4).strip().lower() if match.group(4) else ""

            asset_type = _ASSET_TYPE_MAP.get(raw_type, AssetType.WEB_APPLICATION)
            name = name_part.strip() if name_part else target
            in_scope = "out of scope" not in remainder and "out of scope" not in (name_part or "").lower()

            # Если имя содержит "out of scope", очищаем его
            if name_part and "out of scope" in name_part.lower():
                in_scope = False
                name = target

            assets.append(
                Asset(
                    id=_gen_id(),
                    name=name,
                    asset_type=asset_type,
                    target=target,
                    in_scope=in_scope,
                )
            )

        return assets

    # ------------------------------------------------------------------
    # Парсинг правил
    # ------------------------------------------------------------------

    def _parse_rules(self, section: str) -> list[ProgramRule]:
        """Парсит секцию правил.

        Формат строки: - [ALLOWED] description  или  - [FORBIDDEN] description
        """
        rules: list[ProgramRule] = []
        if not section:
            return rules

        pattern = re.compile(
            r"^-\s+\[(ALLOWED|FORBIDDEN)\]\s+(.+)$",
            re.MULTILINE | re.IGNORECASE,
        )

        for match in pattern.finditer(section):
            tag = match.group(1).upper()
            description = match.group(2).strip()
            is_allowed = tag == "ALLOWED"
            category = self._infer_rule_category(description)

            rules.append(
                ProgramRule(
                    id=_gen_id(),
                    description=description,
                    is_allowed=is_allowed,
                    category=category,
                )
            )

        return rules

    def _infer_rule_category(self, description: str) -> str:
        """Определяет категорию правила по описанию."""
        lower = description.lower()
        if any(w in lower for w in ("scope", "target", "domain", "asset")):
            return "scope"
        if any(w in lower for w in ("disclosure", "report", "publish")):
            return "disclosure"
        if any(w in lower for w in ("test", "scan", "fuzz", "brute", "dos", "ddos")):
            return "testing_method"
        return "general"

    # ------------------------------------------------------------------
    # Парсинг вознаграждений
    # ------------------------------------------------------------------

    def _parse_rewards(self, section: str) -> list[RewardTier]:
        """Парсит секцию вознаграждений.

        Формат строки: - critical: $1000-$5000
        """
        tiers: list[RewardTier] = []
        if not section:
            return tiers

        pattern = re.compile(
            r"^-\s+(\w+):\s*\$?([\d,]+)\s*-\s*\$?([\d,]+)\s*(\w*)",
            re.MULTILINE | re.IGNORECASE,
        )

        for match in pattern.finditer(section):
            raw_severity = match.group(1).lower()
            min_str = match.group(2).replace(",", "")
            max_str = match.group(3).replace(",", "")
            currency = match.group(4).strip().upper() if match.group(4).strip() else "USD"

            severity = _SEVERITY_MAP.get(raw_severity)
            if severity is None:
                continue

            tiers.append(
                RewardTier(
                    severity=severity,
                    min_reward=float(min_str),
                    max_reward=float(max_str),
                    currency=currency,
                )
            )

        return tiers

    # ------------------------------------------------------------------
    # Парсинг требований к раскрытию
    # ------------------------------------------------------------------

    def _parse_disclosure(self, section: str) -> str:
        """Извлекает текст требований к раскрытию."""
        if not section:
            return ""
        # Убираем маркеры списка и возвращаем чистый текст
        lines = []
        for line in section.splitlines():
            cleaned = line.strip()
            if cleaned.startswith("- "):
                cleaned = cleaned[2:]
            if cleaned:
                lines.append(cleaned)
        return "\n".join(lines)
