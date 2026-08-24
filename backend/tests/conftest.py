"""
Shared pytest fixtures.

The fakes here let the storage layer be tested without a live Neo4j: they
record the Cypher that would have been executed so tests can assert on the
generated queries and parameters.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

# Make `app` importable when pytest is invoked from the repository root.
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


class RecordedQuery:
    """A single Cypher statement plus the parameters it was run with."""

    def __init__(self, cypher: str, params: Dict[str, Any]):
        self.cypher = cypher
        self.params = params

    def __repr__(self) -> str:
        return f"RecordedQuery({self.cypher.strip()[:60]!r}, params={list(self.params)})"


class FakeSession:
    """Stands in for a neo4j Session, recording every run() call."""

    def __init__(self, recorder: List[RecordedQuery], results: Optional[List[Any]] = None):
        self._recorder = recorder
        self._results = results if results is not None else []

    def run(self, cypher: str, params: Optional[Dict[str, Any]] = None, **kwargs):
        merged: Dict[str, Any] = dict(params or {})
        merged.update(kwargs)
        self._recorder.append(RecordedQuery(cypher, merged))
        return iter(self._results)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeDriver:
    """Stands in for a neo4j Driver."""

    def __init__(self, recorder: List[RecordedQuery], results: Optional[List[Any]] = None):
        self._recorder = recorder
        self._results = results

    def session(self, **kwargs):
        return FakeSession(self._recorder, self._results)

    def close(self):
        pass

    def verify_connectivity(self):
        pass


@pytest.fixture
def recorded_queries() -> List[RecordedQuery]:
    """Collects the Cypher executed through a fake_neo4j_service."""
    return []


@pytest.fixture
def fake_neo4j_service(recorded_queries, monkeypatch):
    """
    A Neo4jService whose driver is faked out.

    Construction is bypassed with __new__ so no connection is attempted, and
    constraint/index setup is skipped.
    """
    from app.services.neo4j_service import Neo4jService

    service = Neo4jService.__new__(Neo4jService)
    service.driver = FakeDriver(recorded_queries)
    service.uri = "bolt://fake:7687"
    service.user = "neo4j"
    return service


@pytest.fixture
def sample_connections() -> List[Dict[str, Any]]:
    """A small set of parsed connections used across parser/detector tests."""
    return [
        {
            "source_ip": "192.168.1.10",
            "dest_ip": "203.0.113.5",
            "source_port": 51234,
            "dest_port": 443,
            "protocol": "TCP",
            "bytes_sent": 1024,
            "bytes_received": 8192,
            "duration": 1.5,
            "timestamp": "2024-01-01 12:00:00",
            "is_internal_source": True,
            "is_internal_dest": False,
            "is_suspicious_port": False,
            "service": "HTTPS",
        },
        {
            "source_ip": "192.168.1.11",
            "dest_ip": "198.51.100.7",
            "source_port": 40000,
            "dest_port": 4444,
            "protocol": "TCP",
            "bytes_sent": 500,
            "bytes_received": 200,
            "duration": 0.2,
            "timestamp": "2024-01-01 12:01:00",
            "is_internal_source": True,
            "is_internal_dest": False,
            "is_suspicious_port": True,
            "service": "Port-4444",
        },
    ]


@pytest.fixture
def mock_llm():
    """An LLM double whose responses can be scripted per test."""
    llm = MagicMock()
    llm.invoke.return_value = "{}"
    llm.return_value = "{}"
    return llm
