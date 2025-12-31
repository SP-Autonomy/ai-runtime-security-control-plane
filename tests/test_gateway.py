"""
Tests for Gateway Endpoints

Tests the FastAPI gateway including health checks, control endpoints,
and OpenAI-compatible chat completion endpoints.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def test_client():
    """Create test client for gateway."""
    from airs_cp.gateway.app import app
    return TestClient(app)


class TestHealthEndpoints:
    """Tests for health and status endpoints."""
    
    def test_health_check(self, test_client):
        """Test basic health check endpoint."""
        response = test_client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "mode" in data
        assert "provider" in data
        assert "kill_switch" in data
    
    def test_status_endpoint(self, test_client):
        """Test detailed status endpoint."""
        response = test_client.get("/status")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "mode" in data
        assert "provider" in data
        assert "uptime_seconds" in data
        assert "adapters" in data
    
    def test_metrics_endpoint(self, test_client):
        """Test Prometheus metrics endpoint."""
        response = test_client.get("/metrics")
        assert response.status_code == 200
        
        # Prometheus format is plain text
        content = response.text
        assert "airs_uptime_seconds" in content
        assert "airs_kill_switch" in content
        assert "airs_mode_enforce" in content


class TestControlEndpoints:
    """Tests for control plane endpoints."""
    
    def test_mode_change_observe(self, test_client):
        """Test changing mode to observe."""
        response = test_client.post("/mode", json={"mode": "observe"})
        assert response.status_code == 200
        
        data = response.json()
        assert data["mode"] == "observe"
    
    def test_mode_change_enforce(self, test_client):
        """Test changing mode to enforce."""
        response = test_client.post("/mode", json={"mode": "enforce"})
        assert response.status_code == 200
        
        data = response.json()
        assert data["mode"] == "enforce"
        
        # Reset to observe for other tests
        test_client.post("/mode", json={"mode": "observe"})
    
    def test_mode_change_invalid(self, test_client):
        """Test invalid mode value."""
        response = test_client.post("/mode", json={"mode": "invalid"})
        # FastAPI returns 422 for validation errors
        assert response.status_code == 422
    
    def test_kill_switch_activate(self, test_client):
        """Test activating kill switch."""
        response = test_client.post("/kill")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "kill_switch_active"
        assert data["mode"] == "observe"
        
        # Verify mode is effectively observe in health check
        health = test_client.get("/health").json()
        assert health["kill_switch"] is True
        
        # Deactivate for other tests
        test_client.delete("/kill")
    
    def test_kill_switch_deactivate(self, test_client):
        """Test deactivating kill switch."""
        # First activate
        test_client.post("/kill")
        
        # Then deactivate
        response = test_client.delete("/kill")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "normal"
        
        # Verify kill switch is off in health check
        health = test_client.get("/health").json()
        assert health["kill_switch"] is False


class TestOpenAICompatibleEndpoints:
    """Tests for OpenAI-compatible API endpoints."""
    
    def test_models_list(self, test_client):
        """Test listing models endpoint structure."""
        # This may fail if Ollama isn't running, which is expected
        response = test_client.get("/v1/models")
        
        # Should return either success or connection error
        # We're just testing the endpoint structure here
        if response.status_code == 200:
            data = response.json()
            assert "object" in data
            assert data["object"] == "list"
            assert "data" in data
    
    def test_chat_completions_request_format(self, test_client):
        """Test chat completions accepts proper format."""
        # This tests request validation, not actual completion
        request_data = {
            "model": "llama3.2:1b",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ]
        }
        
        # Will fail to connect to Ollama if not running
        # But validates request format is accepted
        response = test_client.post(
            "/v1/chat/completions",
            json=request_data
        )
        
        # Either succeeds or fails with connection error (not validation error)
        assert response.status_code in [200, 500, 502, 503]
    
    def test_chat_completions_invalid_format(self, test_client):
        """Test chat completions rejects invalid format."""
        # Missing required 'messages' field
        request_data = {
            "model": "llama3.2:1b"
        }
        
        response = test_client.post(
            "/v1/chat/completions",
            json=request_data
        )
        
        # Should fail validation
        assert response.status_code == 422


class TestRequestHeaders:
    """Tests for request header handling."""
    
    def test_session_id_header(self, test_client):
        """Test session ID header is accepted."""
        headers = {
            "X-Session-ID": "test-session-123"
        }
        
        response = test_client.get("/health", headers=headers)
        assert response.status_code == 200
    
    def test_trace_id_header(self, test_client):
        """Test trace ID header is accepted."""
        headers = {
            "X-Trace-ID": "trace-abc-123"
        }
        
        response = test_client.get("/health", headers=headers)
        assert response.status_code == 200
    
    def test_tags_header(self, test_client):
        """Test tags header is accepted."""
        headers = {
            "X-Tags": "tag1,tag2,tag3"
        }
        
        response = test_client.get("/health", headers=headers)
        assert response.status_code == 200


class TestErrorHandling:
    """Tests for error handling."""
    
    def test_404_not_found(self, test_client):
        """Test 404 for unknown endpoints."""
        response = test_client.get("/unknown/endpoint")
        assert response.status_code == 404
    
    def test_method_not_allowed(self, test_client):
        """Test 405 for wrong HTTP method."""
        response = test_client.put("/health")
        assert response.status_code == 405
