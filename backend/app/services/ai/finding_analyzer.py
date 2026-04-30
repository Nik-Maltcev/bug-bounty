"""FindingAnalyzer — анализ и триаж находок через LLM.

Определяет реальные уязвимости vs ложные срабатывания,
оценивает серьёзность и эксплуатируемость.
"""

import json
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.ai_schemas import FindingAnalysis, SessionContext
from app.models.database import FindingAnalysisRecord
from app.models.schemas import RawFinding, SeverityLevel
from app.services.ai.llm_provider_manager import LLMProviderManager
from app.services.scanner import Scanner

logger = logging.getLogger(__name__)

FINDING_ANALYSIS_PROMPT = """Ты — эксперт по триажу уязвимостей.
Проанализируй следующую находку безопасности и определи:
1. Это реальная уязвимость или ложное срабатывание?
2. Уровень серьёзности: critical, high, medium, low или informational
3. Эксплуатируемость: easy, moderate, difficult или theoretical
4. Краткое обоснование оценки
5. Признаки ложного срабатывания

Отвечай ТОЛЬКО валидным JSON:
{
  "is_real_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "severity": "critical|high|medium|low|informational",
  "exploitability": "easy|moderate|difficult|theoretical",
  "reasoning": "объяснение",
  "false_positive_indicators": ["признак1", "признак2"]
}"""

VALID_EXPLOITABILITY = {"easy", "moderate", "difficult", "theoretical"}


class FindingAnalyzer:
    """Анализатор находок через LLM."""

    def __init__(self, llm_manager: LLMProviderManager, db_session: Session | None = None):
        self._llm = llm_manager
        self._db = db_session

    def analyze(
        self,
        finding: RawFinding,
        context: SessionContext,
    ) -> FindingAnalysis:
        """Анализирует находку: реальная уязвимость или false positive."""
        try:
            finding_text = (
                f"Type: {finding.vulnerability_type}\n"
                f"Description: {finding.description}\n"
                f"Evidence: {finding.evidence}\n"
                f"Asset: {finding.affected_asset_id}"
            )
            context_text = f"Program: {context.program_name}"
            if context.rules:
                context_text += f"\nRules count: {len(context.rules)}"

            messages = [
                {"role": "system", "content": FINDING_ANALYSIS_PROMPT},
                {"role": "user", "content": f"Context: {context_text}\n\nFinding:\n{finding_text}"},
            ]
            response = self._llm.complete(messages)
            result = self._parse_analysis(response.content)
            return result
        except Exception as e:
            logger.warning(f"LLM finding analysis failed, using fallback: {e}")
            return self.fallback_classify(finding)

    def batch_analyze(
        self,
        findings: list[RawFinding],
        context: SessionContext,
    ) -> list[FindingAnalysis]:
        """Пакетный анализ находок после сканирования."""
        results = []
        for finding in findings:
            result = self.analyze(finding, context)
            results.append(result)
        return results

    def fallback_classify(self, finding: RawFinding) -> FindingAnalysis:
        """Fallback на keyword-based классификацию Scanner.classify_severity."""
        severity = Scanner.classify_severity(finding)
        return FindingAnalysis(
            is_real_vulnerability=severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM),
            confidence=0.5,
            severity=severity,
            exploitability="moderate",
            reasoning=f"Fallback keyword-based classification: {severity.value} [LLM unavailable]",
            false_positive_indicators=[],
        )

    def save_analysis(
        self,
        vulnerability_id: str,
        analysis: FindingAnalysis,
        llm_model: str = "",
        db: Session | None = None,
    ) -> FindingAnalysisRecord | None:
        """Сохраняет результат анализа в БД."""
        session = db or self._db
        if session is None:
            return None
        record = FindingAnalysisRecord(
            id=str(uuid.uuid4()),
            vulnerability_id=vulnerability_id,
            is_real_vulnerability=analysis.is_real_vulnerability,
            confidence=analysis.confidence,
            severity=analysis.severity.value if isinstance(analysis.severity, SeverityLevel) else analysis.severity,
            exploitability=analysis.exploitability,
            reasoning=analysis.reasoning,
            llm_model=llm_model,
            created_at=datetime.now(UTC),
        )
        session.add(record)
        session.commit()
        return record

    @staticmethod
    def _parse_analysis(raw: str) -> FindingAnalysis:
        """Parse LLM JSON response into FindingAnalysis."""
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            json_lines = []
            in_block = False
            for line in lines:
                if line.startswith("```") and not in_block:
                    in_block = True
                    continue
                elif line.startswith("```") and in_block:
                    break
                elif in_block:
                    json_lines.append(line)
            cleaned = "\n".join(json_lines)

        data = json.loads(cleaned)

        severity_str = data.get("severity", "informational").lower()
        try:
            severity = SeverityLevel(severity_str)
        except ValueError:
            severity = SeverityLevel.INFORMATIONAL

        exploitability = data.get("exploitability", "theoretical")
        if exploitability not in VALID_EXPLOITABILITY:
            exploitability = "theoretical"

        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        return FindingAnalysis(
            is_real_vulnerability=bool(data.get("is_real_vulnerability", False)),
            confidence=confidence,
            severity=severity,
            exploitability=exploitability,
            reasoning=str(data.get("reasoning", "")),
            false_positive_indicators=data.get("false_positive_indicators", []),
        )
