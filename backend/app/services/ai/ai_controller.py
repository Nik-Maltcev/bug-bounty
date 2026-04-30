"""AIController — центральный контроллер AI-операций.

Фасад, координирующий все AI-операции: обработка сообщений чата,
сборка контекста, маршрутизация, управление историей диалогов.
"""

import json
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.ai_exceptions import InputTooLongError
from app.models.ai_schemas import (
    ChatMessage,
    ChatResponse,
    FindingAnalysis,
    IntentType,
    SessionContext,
)
from app.models.database import (
    ConversationMessage,
    FindingAnalysisRecord,
    Program,
    VulnerabilityRecord,
)
from app.models.database import Asset as AssetDB
from app.models.database import ProgramRule as ProgramRuleDB
from app.models.database import Scan as ScanDB
from app.models.schemas import ProgramRule, RawFinding
from app.services.ai.finding_analyzer import FindingAnalyzer
from app.services.ai.intent_router import IntentRouter
from app.services.ai.llm_provider_manager import LLMProviderManager
from app.services.ai.prompt_sanitizer import PromptSanitizer
from app.services.ai.rule_analyzer import RuleAnalyzer
from app.services.ai.ai_report_generator import AIReportGenerator
from app.services.audit_logger import AuditLogger
from app.services.compliance_manager import ComplianceManager
from app.services.report_generator import ReportGenerator
from app.services.scanner import Scanner

logger = logging.getLogger(__name__)

MAX_CONTEXT_MESSAGES = 20
MAX_INPUT_LENGTH = 10000
MIN_COMPRESSED_MESSAGES = 5


class AIController:
    """Центральный контроллер AI-операций."""

    def __init__(
        self,
        llm_manager: LLMProviderManager,
        scanner: Scanner | None = None,
        compliance_manager: ComplianceManager | None = None,
        report_generator: ReportGenerator | None = None,
        audit_logger: AuditLogger | None = None,
        db: Session | None = None,
    ):
        self._llm = llm_manager
        self._scanner = scanner or Scanner()
        self._compliance = compliance_manager or ComplianceManager()
        self._report_gen = report_generator or ReportGenerator()
        self._audit = audit_logger or AuditLogger()
        self._db = db
        self._sanitizer = PromptSanitizer()
        self._intent_router = IntentRouter(llm_manager)
        self._rule_analyzer = RuleAnalyzer(llm_manager, self._compliance)
        self._finding_analyzer = FindingAnalyzer(llm_manager, db)
        self._ai_report_gen = AIReportGenerator(llm_manager, self._report_gen)

    def handle_message(
        self,
        program_id: str,
        user_message: str,
    ) -> ChatResponse:
        """Обрабатывает сообщение пользователя — полный цикл."""
        # 1. Validate length
        if not self._sanitizer.validate_length(user_message):
            raise InputTooLongError(len(user_message), MAX_INPUT_LENGTH)

        # 2. Sanitize
        sanitized = self._sanitizer.sanitize(user_message)
        sanitized = self._sanitizer.strip_sensitive_data(sanitized)

        # 3. Save user message
        self._save_message(program_id, "user", user_message)

        # 4. Build context
        context = self.build_session_context(program_id)

        # 5. Route intent
        parsed = self._intent_router.classify(sanitized, context)

        # 6. Execute action based on intent
        response_text = self._execute_intent(parsed.intent, parsed.params, context, sanitized)

        # 7. Save assistant message
        self._save_message(program_id, "assistant", response_text, intent=parsed.intent.value)

        return ChatResponse(
            message=response_text,
            intent=parsed.intent.value,
            metadata=parsed.params,
        )

    def build_session_context(self, program_id: str) -> SessionContext:
        """Собирает контекст сессии для программы."""
        if self._db is None:
            return SessionContext(
                program_id=program_id,
                program_name="Unknown",
            )

        program = self._db.query(Program).filter(Program.id == program_id).first()
        program_name = program.name if program else "Unknown"

        # Rules
        rule_rows = self._db.query(ProgramRuleDB).filter(
            ProgramRuleDB.program_id == program_id
        ).all()
        rules = [
            {"id": r.id, "description": r.description, "is_allowed": r.is_allowed, "category": r.category}
            for r in rule_rows
        ]

        # Assets
        asset_rows = self._db.query(AssetDB).filter(AssetDB.program_id == program_id).all()
        assets = [
            {"id": a.id, "name": a.name, "asset_type": a.asset_type, "target": a.target, "in_scope": a.in_scope}
            for a in asset_rows
        ]

        # Recent findings
        vuln_rows = self._db.query(VulnerabilityRecord).filter(
            VulnerabilityRecord.program_id == program_id
        ).order_by(VulnerabilityRecord.created_at.desc()).limit(10).all()
        findings = [
            {"id": v.id, "type": v.vulnerability_type, "severity": v.severity, "status": v.status}
            for v in vuln_rows
        ]

        # Recent scans
        scan_rows = self._db.query(ScanDB).filter(
            ScanDB.program_id == program_id
        ).order_by(ScanDB.id.desc()).limit(5).all()
        scans = [
            {"id": s.id, "status": s.status, "stage": s.current_stage}
            for s in scan_rows
        ]

        # Conversation history
        msg_rows = self._db.query(ConversationMessage).filter(
            ConversationMessage.program_id == program_id
        ).order_by(ConversationMessage.created_at.desc()).limit(MAX_CONTEXT_MESSAGES).all()
        history = [
            {"role": m.role, "content": m.content}
            for m in reversed(msg_rows)
        ]

        return SessionContext(
            program_id=program_id,
            program_name=program_name,
            rules=rules,
            assets=assets,
            recent_findings=findings,
            recent_scans=scans,
            conversation_history=history,
        )

    def compress_context(self, context: SessionContext, max_tokens: int) -> SessionContext:
        """Сжимает контекст при превышении лимита.

        Приоритет: rules полностью, последние 5 сообщений минимум.
        """
        # Estimate token count (rough: 1 token ≈ 4 chars)
        def estimate_tokens(obj) -> int:
            return len(json.dumps(obj, default=str)) // 4

        total = estimate_tokens(context.model_dump())
        if total <= max_tokens:
            return context

        # Keep rules fully, trim other fields
        compressed = context.model_copy()

        # Trim findings to 5
        if len(compressed.recent_findings) > 5:
            compressed.recent_findings = compressed.recent_findings[:5]

        # Trim scans to 3
        if len(compressed.recent_scans) > 3:
            compressed.recent_scans = compressed.recent_scans[:3]

        # Trim assets to 5
        if len(compressed.assets) > 5:
            compressed.assets = compressed.assets[:5]

        # Keep at least last 5 messages
        if len(compressed.conversation_history) > MIN_COMPRESSED_MESSAGES:
            compressed.conversation_history = compressed.conversation_history[-MIN_COMPRESSED_MESSAGES:]

        return compressed

    def get_conversation_history(self, program_id: str, limit: int = 50) -> list[ChatMessage]:
        """Загружает историю диалога для программы."""
        if self._db is None:
            return []

        rows = self._db.query(ConversationMessage).filter(
            ConversationMessage.program_id == program_id
        ).order_by(ConversationMessage.created_at.asc()).limit(limit).all()

        return [
            ChatMessage(
                id=m.id,
                program_id=m.program_id,
                role=m.role,
                content=m.content,
                intent=m.intent,
                metadata=json.loads(m.metadata_json) if m.metadata_json else {},
                created_at=m.created_at,
            )
            for m in rows
        ]

    def clear_conversation_history(self, program_id: str) -> None:
        """Очищает историю диалога для программы."""
        if self._db is None:
            return
        self._db.query(ConversationMessage).filter(
            ConversationMessage.program_id == program_id
        ).delete()
        self._db.commit()

    def generate_recommendations(
        self,
        program_id: str,
        context: SessionContext | None = None,
    ) -> str:
        """Генерирует рекомендации следующих шагов через LLM."""
        if context is None:
            context = self.build_session_context(program_id)

        # Load rules for filtering
        rules = self._load_program_rules(program_id)

        context_text = f"Program: {context.program_name}\n"
        if context.recent_findings:
            context_text += f"Recent findings: {json.dumps(context.recent_findings[:5], default=str)}\n"
        if context.recent_scans:
            context_text += f"Recent scans: {json.dumps(context.recent_scans[:3], default=str)}\n"
        if rules:
            forbidden = [r.description for r in rules if not r.is_allowed]
            if forbidden:
                context_text += f"FORBIDDEN actions: {'; '.join(forbidden)}\n"

        try:
            messages = [
                {"role": "system", "content": "Ты — эксперт по безопасности веб-сайтов. Предложи следующие шаги на основе текущих находок. НИКОГДА не рекомендуй действия, запрещённые правилами программы. Отвечай на русском языке."},
                {"role": "user", "content": f"{context_text}\nЧто проверить дальше?"},
            ]
            response = self._llm.complete(messages)
            return response.content
        except Exception as e:
            logger.warning(f"Recommendations generation failed: {e}")
            return "Не удалось сгенерировать рекомендации. Проверьте находки вручную."

    def _execute_intent(
        self,
        intent: IntentType,
        params: dict,
        context: SessionContext,
        message: str,
    ) -> str:
        """Выполняет действие на основе намерения."""
        try:
            if intent == IntentType.QUERY_RULES:
                rules = self._load_program_rules(context.program_id)
                return self._rule_analyzer.answer_rule_question(message, rules)

            elif intent == IntentType.RECOMMENDATIONS:
                return self.generate_recommendations(context.program_id, context)

            elif intent == IntentType.CLEAR_HISTORY:
                self.clear_conversation_history(context.program_id)
                return "История чата очищена."

            elif intent == IntentType.QUERY_RESULTS:
                return self._handle_query_results(context)

            elif intent == IntentType.GENERATE_REPORT:
                return self._handle_generate_report(params, context)

            elif intent == IntentType.ANALYZE_FINDING:
                return self._handle_analyze_finding(params, context)

            elif intent == IntentType.SCAN:
                return self._handle_scan_request(params, context)

            else:  # GENERAL
                return self._handle_general(message, context)

        except Exception as e:
            logger.error(f"Intent execution failed: {e}")
            return f"Произошла ошибка при обработке запроса. Попробуйте ещё раз."

    def _handle_query_results(self, context: SessionContext) -> str:
        if not context.recent_findings:
            return "Находки для этой программы пока не обнаружены."
        summary = []
        for f in context.recent_findings[:10]:
            summary.append(f"- [{f.get('severity', 'unknown').upper()}] {f.get('type', 'unknown')} (status: {f.get('status', 'new')})")
        return "Последние находки:\n" + "\n".join(summary)

    def _handle_generate_report(self, params: dict, context: SessionContext) -> str:
        return "Для генерации отчёта используйте эндпоинт: POST /api/ai/report/{vuln_id}"

    def _handle_analyze_finding(self, params: dict, context: SessionContext) -> str:
        return "Для анализа находки используйте: POST /api/ai/analyze/finding/{id}"

    def _handle_scan_request(self, params: dict, context: SessionContext) -> str:
        target = params.get("target", "")
        if target:
            return f"Для запуска сканирования {target} используйте страницу Сканирования или API: POST /api/programs/{{program_id}}/scans"
        return "Укажите цель для сканирования. Пример: 'Просканируй example.com на XSS'"

    def _handle_general(self, message: str, context: SessionContext) -> str:
        try:
            ctx_text = f"Program: {context.program_name}"
            if context.recent_findings:
                ctx_text += f"\nFindings: {len(context.recent_findings)}"
            messages = [
                {"role": "system", "content": "Ты — помощник по безопасности веб-сайтов. Отвечай на вопросы пользователя на основе предоставленного контекста. Отвечай на русском языке."},
                {"role": "user", "content": f"Context: {ctx_text}\n\nQuestion: {message}"},
            ]
            response = self._llm.complete(messages)
            return response.content
        except Exception:
            return "Не удалось подключиться к AI-сервису. Проверьте настройки LLM."

    def _save_message(
        self,
        program_id: str,
        role: str,
        content: str,
        intent: str | None = None,
    ) -> None:
        if self._db is None:
            return
        msg = ConversationMessage(
            id=str(uuid.uuid4()),
            program_id=program_id,
            role=role,
            content=content,
            intent=intent,
            metadata_json="{}",
            created_at=datetime.now(UTC),
        )
        self._db.add(msg)
        self._db.commit()

    def _load_program_rules(self, program_id: str) -> list[ProgramRule]:
        if self._db is None:
            return []
        return self._compliance.load_program_rules(program_id, self._db)
