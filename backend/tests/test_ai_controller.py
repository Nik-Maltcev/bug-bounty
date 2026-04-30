"""Tests for AIController — central AI controller with mocked LLM."""

import json
import pytest
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.models.ai_schemas import (
    ChatMessage,
    ChatResponse,
    IntentType,
    LLMResponse,
    ParsedIntent,
    ProviderType,
    SessionContext,
)
from app.models.database import Base, ConversationMessage, Program
from app.services.ai.ai_controller import AIController


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    yield session
    session.close()


@pytest.fixture
def program(db_session):
    p = Program(
        id="prog-1", name="Test Program", platform="hackerone",
        disclosure_requirements="Responsible disclosure",
        raw_text="test", created_at=datetime.now(UTC),
    )
    db_session.add(p)
    db_session.commit()
    return p


def _mock_llm():
    mgr = MagicMock()
    mgr.complete.return_value = LLMResponse(
        content="Test response from AI",
        model="test-model",
        usage={},
        provider=ProviderType.DEEPSEEK,
    )
    return mgr


class TestHandleMessage:
    def test_basic_message_flow(self, db_session, program):
        llm = _mock_llm()
        # Mock intent router to return GENERAL
        controller = AIController(llm_manager=llm, db=db_session)
        with patch.object(controller._intent_router, 'classify') as mock_classify:
            mock_classify.return_value = ParsedIntent(
                intent=IntentType.GENERAL, params={}, confidence=0.8
            )
            response = controller.handle_message("prog-1", "Hello, what can you do?")

        assert isinstance(response, ChatResponse)
        assert response.intent == "general"
        assert response.message != ""

    def test_saves_messages_to_db(self, db_session, program):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        with patch.object(controller._intent_router, 'classify') as mock_classify:
            mock_classify.return_value = ParsedIntent(
                intent=IntentType.GENERAL, params={}, confidence=0.8
            )
            controller.handle_message("prog-1", "Test message")

        messages = db_session.query(ConversationMessage).filter(
            ConversationMessage.program_id == "prog-1"
        ).all()
        assert len(messages) == 2  # user + assistant
        roles = {m.role for m in messages}
        assert "user" in roles
        assert "assistant" in roles

    def test_clear_history_intent(self, db_session, program):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        # Add some messages first
        controller._save_message("prog-1", "user", "old message")
        controller._save_message("prog-1", "assistant", "old response")

        with patch.object(controller._intent_router, 'classify') as mock_classify:
            mock_classify.return_value = ParsedIntent(
                intent=IntentType.CLEAR_HISTORY, params={}, confidence=0.9
            )
            response = controller.handle_message("prog-1", "Clear history")

        assert "очищена" in response.message.lower()

    def test_input_too_long_raises(self, db_session, program):
        from app.core.ai_exceptions import InputTooLongError
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        with pytest.raises(InputTooLongError):
            controller.handle_message("prog-1", "x" * 10001)


class TestBuildSessionContext:
    def test_builds_context_for_program(self, db_session, program):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        context = controller.build_session_context("prog-1")
        assert isinstance(context, SessionContext)
        assert context.program_id == "prog-1"
        assert context.program_name == "Test Program"

    def test_context_without_db(self):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=None)
        context = controller.build_session_context("prog-1")
        assert context.program_name == "Unknown"


class TestCompressContext:
    def test_compress_preserves_rules(self, db_session):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        context = SessionContext(
            program_id="p1",
            program_name="Test",
            rules=[{"id": f"R{i}", "description": f"Rule {i}" * 100} for i in range(20)],
            assets=[{"id": f"A{i}"} for i in range(20)],
            recent_findings=[{"id": f"F{i}"} for i in range(20)],
            recent_scans=[{"id": f"S{i}"} for i in range(10)],
            conversation_history=[{"role": "user", "content": f"msg {i}" * 50} for i in range(20)],
        )
        compressed = controller.compress_context(context, max_tokens=500)
        # Rules must be preserved fully
        assert len(compressed.rules) == 20
        # History must have at least 5
        assert len(compressed.conversation_history) >= 5

    def test_no_compression_needed(self, db_session):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        context = SessionContext(
            program_id="p1", program_name="Test",
            rules=[{"id": "R1"}],
            conversation_history=[{"role": "user", "content": "hi"}],
        )
        compressed = controller.compress_context(context, max_tokens=100000)
        assert compressed.rules == context.rules


class TestConversationHistory:
    def test_get_history(self, db_session, program):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        controller._save_message("prog-1", "user", "Hello")
        controller._save_message("prog-1", "assistant", "Hi there")

        history = controller.get_conversation_history("prog-1")
        assert len(history) == 2
        assert history[0].role == "user"
        assert history[1].role == "assistant"

    def test_clear_history(self, db_session, program):
        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        controller._save_message("prog-1", "user", "Hello")
        controller.clear_conversation_history("prog-1")

        history = controller.get_conversation_history("prog-1")
        assert len(history) == 0

    def test_program_isolation(self, db_session):
        # Create two programs
        p1 = Program(id="p1", name="P1", platform="test", created_at=datetime.now(UTC))
        p2 = Program(id="p2", name="P2", platform="test", created_at=datetime.now(UTC))
        db_session.add_all([p1, p2])
        db_session.commit()

        llm = _mock_llm()
        controller = AIController(llm_manager=llm, db=db_session)
        controller._save_message("p1", "user", "Message for P1")
        controller._save_message("p2", "user", "Message for P2")

        h1 = controller.get_conversation_history("p1")
        h2 = controller.get_conversation_history("p2")
        assert len(h1) == 1
        assert len(h2) == 1
        assert h1[0].content == "Message for P1"
        assert h2[0].content == "Message for P2"

        # Clear P1 doesn't affect P2
        controller.clear_conversation_history("p1")
        assert len(controller.get_conversation_history("p1")) == 0
        assert len(controller.get_conversation_history("p2")) == 1
