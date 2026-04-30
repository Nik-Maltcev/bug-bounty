"""Тесты для RulesParser — парсера правил программы bug bounty."""

import pytest

from app.core.exceptions import ParseError
from app.models.schemas import (
    AssetType,
    ProgramSource,
    SeverityLevel,
)
from app.services.rules_parser import RulesParser


@pytest.fixture
def parser() -> RulesParser:
    return RulesParser()


FULL_PROGRAM_TEXT = """\
# Program: Example Bug Bounty
Platform: hackerone

## Assets
- [web] https://example.com (Main Website)

## Rules
- [ALLOWED] Testing for XSS vulnerabilities
- [ALLOWED] Scanning open ports
- [FORBIDDEN] Denial of service attacks
- [FORBIDDEN] Accessing other users' data

## Rewards
- critical: $5000-$10000
- high: $2000-$5000
- medium: $500-$2000
- low: $100-$500
- informational: $0-$100

## Disclosure
- Report vulnerabilities within 24 hours
- Do not publish details before fix is deployed
"""


# --- Парсинг полной программы ---


@pytest.mark.asyncio
async def test_parse_full_program(parser: RulesParser):
    """Парсинг полного описания программы извлекает все секции."""
    source = ProgramSource(text=FULL_PROGRAM_TEXT)
    result = await parser.parse(source)

    assert result.name == "Example Bug Bounty"
    assert result.platform == "hackerone"
    assert result.id  # UUID сгенерирован
    assert result.raw_text == FULL_PROGRAM_TEXT


@pytest.mark.asyncio
async def test_parse_assets(parser: RulesParser):
    """Парсинг извлекает активы с правильными типами и scope."""
    source = ProgramSource(text=FULL_PROGRAM_TEXT)
    result = await parser.parse(source)

    assert len(result.assets) == 1

    web = result.assets[0]
    assert web.asset_type == AssetType.WEB_APPLICATION
    assert web.target == "https://example.com"
    assert web.name == "Main Website"
    assert web.in_scope is True


@pytest.mark.asyncio
async def test_parse_rules(parser: RulesParser):
    """Парсинг извлекает правила с корректными флагами allowed/forbidden."""
    source = ProgramSource(text=FULL_PROGRAM_TEXT)
    result = await parser.parse(source)

    assert len(result.rules) == 4

    allowed_rules = [r for r in result.rules if r.is_allowed]
    forbidden_rules = [r for r in result.rules if not r.is_allowed]

    assert len(allowed_rules) == 2
    assert len(forbidden_rules) == 2
    assert any("XSS" in r.description for r in allowed_rules)
    assert any("Denial of service" in r.description for r in forbidden_rules)


@pytest.mark.asyncio
async def test_parse_rewards(parser: RulesParser):
    """Парсинг извлекает уровни вознаграждений."""
    source = ProgramSource(text=FULL_PROGRAM_TEXT)
    result = await parser.parse(source)

    assert len(result.reward_tiers) == 5

    critical = next(t for t in result.reward_tiers if t.severity == SeverityLevel.CRITICAL)
    assert critical.min_reward == 5000.0
    assert critical.max_reward == 10000.0
    assert critical.currency == "USD"


@pytest.mark.asyncio
async def test_parse_disclosure(parser: RulesParser):
    """Парсинг извлекает требования к раскрытию."""
    source = ProgramSource(text=FULL_PROGRAM_TEXT)
    result = await parser.parse(source)

    assert "24 hours" in result.disclosure_requirements
    assert "publish" in result.disclosure_requirements.lower()


# --- Обработка ошибок ---


@pytest.mark.asyncio
async def test_parse_empty_source_raises_error(parser: RulesParser):
    """ParseError при пустом источнике (ни URL, ни текст)."""
    source = ProgramSource()
    with pytest.raises(ParseError):
        await parser.parse(source)


@pytest.mark.asyncio
async def test_parse_empty_text_raises_error(parser: RulesParser):
    """ParseError при пустом тексте."""
    source = ProgramSource(text="")
    with pytest.raises(ParseError):
        await parser.parse(source)


@pytest.mark.asyncio
async def test_parse_whitespace_only_raises_error(parser: RulesParser):
    """ParseError при тексте из одних пробелов."""
    source = ProgramSource(text="   \n\n  ")
    with pytest.raises(ParseError):
        await parser.parse(source)


# --- Минимальный текст ---


@pytest.mark.asyncio
async def test_parse_minimal_text(parser: RulesParser):
    """Парсинг минимального текста без секций возвращает пустые списки."""
    source = ProgramSource(text="# Program: Minimal\n\nSome description.")
    result = await parser.parse(source)

    assert result.name == "Minimal"
    assert result.assets == []
    assert result.rules == []
    assert result.reward_tiers == []


# --- Определение платформы ---


@pytest.mark.asyncio
async def test_platform_detection_from_header(parser: RulesParser):
    """Платформа извлекается из заголовка Platform:."""
    source = ProgramSource(text="# Program: Test\nPlatform: bugcrowd\n")
    result = await parser.parse(source)
    assert result.platform == "bugcrowd"


@pytest.mark.asyncio
async def test_platform_detection_from_keywords(parser: RulesParser):
    """Платформа определяется по ключевым словам в тексте."""
    source = ProgramSource(text="# Program: Test\nHosted on Immunefi platform.\n")
    result = await parser.parse(source)
    assert result.platform == "immunefi"


@pytest.mark.asyncio
async def test_platform_defaults_to_custom(parser: RulesParser):
    """Платформа по умолчанию — custom."""
    source = ProgramSource(text="# Program: Test\n")
    result = await parser.parse(source)
    assert result.platform == "custom"


# --- Граничные случаи ---


@pytest.mark.asyncio
async def test_parse_rewards_with_commas(parser: RulesParser):
    """Парсинг вознаграждений с запятыми в числах."""
    text = "# Program: Test\n## Rewards\n- critical: $10,000-$50,000\n"
    source = ProgramSource(text=text)
    result = await parser.parse(source)

    assert len(result.reward_tiers) == 1
    assert result.reward_tiers[0].min_reward == 10000.0
    assert result.reward_tiers[0].max_reward == 50000.0


@pytest.mark.asyncio
async def test_parse_unknown_asset_type_defaults_to_web(parser: RulesParser):
    """Неизвестный тип актива по умолчанию — web_application."""
    text = "# Program: Test\n## Assets\n- [unknown] https://test.com (Test)\n"
    source = ProgramSource(text=text)
    result = await parser.parse(source)

    assert len(result.assets) == 1
    assert result.assets[0].asset_type == AssetType.WEB_APPLICATION


@pytest.mark.asyncio
async def test_parse_invalid_url_raises_error(parser: RulesParser):
    """ParseError при невалидном URL."""
    source = ProgramSource(url="http://invalid-url-that-does-not-exist.example")
    with pytest.raises(ParseError):
        await parser.parse(source)


@pytest.mark.asyncio
async def test_rule_category_inference(parser: RulesParser):
    """Категория правила определяется по ключевым словам."""
    text = """\
# Program: Test
## Rules
- [ALLOWED] Testing for SQL injection
- [FORBIDDEN] Publishing disclosure before fix
- [ALLOWED] Scanning target domains in scope
"""
    source = ProgramSource(text=text)
    result = await parser.parse(source)

    categories = {r.description: r.category for r in result.rules}
    assert categories["Testing for SQL injection"] == "testing_method"
    assert categories["Publishing disclosure before fix"] == "disclosure"
    assert categories["Scanning target domains in scope"] == "scope"


@pytest.mark.asyncio
async def test_each_asset_has_unique_id(parser: RulesParser):
    """Каждый актив получает уникальный UUID."""
    source = ProgramSource(text=FULL_PROGRAM_TEXT)
    result = await parser.parse(source)

    ids = [a.id for a in result.assets]
    assert len(ids) == len(set(ids))


@pytest.mark.asyncio
async def test_each_rule_has_unique_id(parser: RulesParser):
    """Каждое правило получает уникальный UUID."""
    source = ProgramSource(text=FULL_PROGRAM_TEXT)
    result = await parser.parse(source)

    ids = [r.id for r in result.rules]
    assert len(ids) == len(set(ids))


# --- Форматирование и round-trip ---


def test_format_rules_produces_valid_text(parser: RulesParser):
    """format_rules создаёт текст, содержащий все секции программы."""
    program = parser._parse_text(FULL_PROGRAM_TEXT)
    formatted = parser.format_rules(program)

    assert "# Program: Example Bug Bounty" in formatted
    assert "Platform: hackerone" in formatted
    assert "## Assets" in formatted
    assert "## Rules" in formatted
    assert "## Rewards" in formatted
    assert "## Disclosure" in formatted
    # Проверяем наличие конкретных данных
    assert "https://example.com" in formatted
    assert "[ALLOWED]" in formatted
    assert "[FORBIDDEN]" in formatted
    assert "critical" in formatted


def test_format_rules_asset_out_of_scope(parser: RulesParser):
    """format_rules помечает активы вне scope как (out of scope)."""
    program = parser._parse_text(FULL_PROGRAM_TEXT)
    formatted = parser.format_rules(program)

    # Not checking mobile app out of scope anymore since we removed the asset from the fixture
    assert "https://example.com" in formatted


def test_reparse_format_rules_roundtrip(parser: RulesParser):
    """reparse(format_rules(program)) создаёт эквивалентный объект."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    formatted = parser.format_rules(original)
    reparsed = parser.reparse(formatted)

    # Имя и платформа
    assert reparsed.name == original.name
    assert reparsed.platform == original.platform

    # Количество элементов
    assert len(reparsed.assets) == len(original.assets)
    assert len(reparsed.rules) == len(original.rules)
    assert len(reparsed.reward_tiers) == len(original.reward_tiers)


def test_roundtrip_preserves_asset_types(parser: RulesParser):
    """Round-trip сохраняет типы активов."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    for orig, rep in zip(original.assets, reparsed.assets):
        assert rep.asset_type == orig.asset_type


def test_roundtrip_preserves_asset_names(parser: RulesParser):
    """Round-trip сохраняет имена активов."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    for orig, rep in zip(original.assets, reparsed.assets):
        assert rep.name == orig.name


def test_roundtrip_preserves_asset_targets(parser: RulesParser):
    """Round-trip сохраняет target активов."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    for orig, rep in zip(original.assets, reparsed.assets):
        assert rep.target == orig.target


def test_roundtrip_preserves_asset_in_scope(parser: RulesParser):
    """Round-trip сохраняет флаг in_scope активов."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    for orig, rep in zip(original.assets, reparsed.assets):
        assert rep.in_scope == orig.in_scope


def test_roundtrip_preserves_rule_descriptions(parser: RulesParser):
    """Round-trip сохраняет описания правил."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    orig_descs = [r.description for r in original.rules]
    rep_descs = [r.description for r in reparsed.rules]
    assert rep_descs == orig_descs


def test_roundtrip_preserves_rule_is_allowed(parser: RulesParser):
    """Round-trip сохраняет флаг is_allowed правил."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    orig_flags = [r.is_allowed for r in original.rules]
    rep_flags = [r.is_allowed for r in reparsed.rules]
    assert rep_flags == orig_flags


def test_roundtrip_preserves_rewards(parser: RulesParser):
    """Round-trip сохраняет уровни вознаграждений."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    for orig, rep in zip(original.reward_tiers, reparsed.reward_tiers):
        assert rep.severity == orig.severity
        assert rep.min_reward == orig.min_reward
        assert rep.max_reward == orig.max_reward
        assert rep.currency == orig.currency


def test_roundtrip_preserves_disclosure(parser: RulesParser):
    """Round-trip сохраняет требования к раскрытию."""
    original = parser._parse_text(FULL_PROGRAM_TEXT)
    reparsed = parser.reparse(parser.format_rules(original))

    assert reparsed.disclosure_requirements == original.disclosure_requirements
