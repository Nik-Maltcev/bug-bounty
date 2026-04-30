"""Tests for AI API endpoints with mocked AIController and LLM."""

import json
import pytest
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import get_db
from app.main import app
from app.models.database import Base, Program


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session_ = sessionmaker(bind=engine)
    session = Session_()
    yield session
    session.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def program(db_session):
    p = Program(
        id="prog-1", name="Test Program", platform="hackerone",
        disclosure_requirements="test", raw_text="test",
        created_at=datetime.now(UTC),
    )
    db_session.add(p)
    db_session.commit()
    return p


class TestChatEndpoints:
    @patch("app.api.ai._get_controller")
    def test_send_message(self, mock_ctrl, client, program):
        from app.models.ai_schemas import ChatResponse
        controller = MagicMock()
        controller.handle_message.return_value = ChatResponse(
            message="Hello! I can help with security testing.",
            intent="general",
            metadata={},
        )
        mock_ctrl.return_value = controller

        resp = client.post("/api/ai/chat", json={
            "program_id": "prog-1",
            "message": "Hello",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["message"] == "Hello! I can help with security testing."
        assert data["intent"] == "general"

    @patch("app.api.ai._get_controller")
    def test_get_history(self, mock_ctrl, client, program):
        from app.models.ai_schemas import ChatMessage
        controller = MagicMock()
        controller.get_conversation_history.return_value = [
            ChatMessage(
                id="m1", program_id="prog-1", role="user",
                content="Hello", metadata={},
                created_at=datetime.now(UTC),
            ),
        ]
        mock_ctrl.return_value = controller

        resp = client.get("/api/ai/chat/prog-1/history")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["role"] == "user"

    @patch("app.api.ai._get_controller")
    def test_clear_history(self, mock_ctrl, client, program):
        controller = MagicMock()
        mock_ctrl.return_value = controller

        resp = client.delete("/api/ai/chat/prog-1/history")
        assert resp.status_code == 200
        controller.clear_conversation_history.assert_called_once_with("prog-1")


class TestSettingsEndpoints:
    @patch("app.api.ai._get_llm_manager")
    def test_get_settings_default(self, mock_mgr, client):
        mgr = MagicMock()
        mgr.load_provider_config.return_value = None
        mock_mgr.return_value = mgr

        resp = client.get("/api/ai/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "deepseek"
        assert data["is_connected"] is False

    @patch("app.api.ai._get_llm_manager")
    def test_update_settings(self, mock_mgr, client):
        mgr = MagicMock()
        mock_mgr.return_value = mgr

        resp = client.put("/api/ai/settings", json={
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4o",
            "api_key": "sk-test",
            "max_tokens": 4096,
            "temperature": 0.3,
        })
        assert resp.status_code == 200
        mgr.save_provider_config.assert_called_once()

    @patch("app.api.ai._get_llm_manager")
    def test_test_connection(self, mock_mgr, client):
        mgr = MagicMock()
        mgr.load_provider_config.return_value = MagicMock()
        mgr.test_connection.return_value = True
        mock_mgr.return_value = mgr

        resp = client.post("/api/ai/settings/test")
        assert resp.status_code == 200
        assert resp.json()["connected"] is True


class TestAnalysisEndpoints:
    @patch("app.api.ai._get_llm_manager")
    def test_analyze_finding_not_found(self, mock_mgr, client, program):
        """Finding not found should return 404."""
        # The endpoint queries VulnerabilityRecord directly from DB
        # Since we have a clean test DB with no vulnerabilities, it should 404
        resp = client.post("/api/ai/analyze/finding/nonexistent")
        assert resp.status_code == 404

    def test_analyze_rules_missing_params(self, client):
        resp = client.post("/api/ai/analyze/rules", json={})
        assert resp.status_code == 400

    @patch("app.api.ai._get_controller")
    def test_recommendations(self, mock_ctrl, client, program):
        controller = MagicMock()
        controller.generate_recommendations.return_value = "Check for XSS on /search"
        mock_ctrl.return_value = controller

        resp = client.post("/api/ai/recommendations/prog-1")
        assert resp.status_code == 200
        assert "recommendations" in resp.json()


class TestExceptionHandlers:
    def test_input_too_long(self, client):
        """Message exceeding max_length should be rejected by Pydantic validation."""
        resp = client.post("/api/ai/chat", json={
            "program_id": "prog-1",
            "message": "x" * 10001,
        })
        assert resp.status_code == 422  # Pydantic validation error

    @patch("app.api.ai._get_controller")
    def test_llm_provider_error_returns_502(self, mock_ctrl, client):
        from app.core.ai_exceptions import LLMProviderError
        controller = MagicMock()
        controller.handle_message.side_effect = LLMProviderError("deepseek", "Connection failed")
        mock_ctrl.return_value = controller

        resp = client.post("/api/ai/chat", json={
            "program_id": "prog-1",
            "message": "Hello",
        })
        assert resp.status_code == 502

    @patch("app.api.ai._get_controller")
    def test_llm_rate_limit_returns_429(self, mock_ctrl, client):
        from app.core.ai_exceptions import LLMRateLimitError
        controller = MagicMock()
        controller.handle_message.side_effect = LLMRateLimitError("deepseek")
        mock_ctrl.return_value = controller

        resp = client.post("/api/ai/chat", json={
            "program_id": "prog-1",
            "message": "Hello",
        })
        assert resp.status_code == 429
