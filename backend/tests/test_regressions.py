"""
Regression tests for defects found during the completeness audit.

Each test here pins a specific bug that was fixed. They are deliberately
low-level (asserting on generated Cypher, not on database state) so the whole
file runs without a live Neo4j.
"""

import inspect
import re

import pytest


# =============================================================================
# 1. Neo4jService.execute_query existed only as a caller, never as a method
# =============================================================================

class TestExecuteQueryExists:
    """network.py called neo4j_service.execute_query(); the method was missing."""

    def test_execute_query_is_defined(self):
        from app.services.neo4j_service import Neo4jService

        assert hasattr(Neo4jService, "execute_query")
        assert callable(Neo4jService.execute_query)

    def test_execute_query_does_not_require_graph_id(self):
        """It is the cross-graph escape hatch, so graph_id must not be required."""
        from app.services.neo4j_service import Neo4jService

        params = inspect.signature(Neo4jService.execute_query).parameters
        assert "cypher_query" in params
        assert "graph_id" not in params

    def test_execute_query_runs_and_returns_records(self, fake_neo4j_service, recorded_queries):
        result = fake_neo4j_service.execute_query(
            "MATCH (n) RETURN n LIMIT 1", {"x": 1}
        )

        assert result == []
        assert len(recorded_queries) == 1
        assert recorded_queries[0].params == {"x": 1}

    def test_execute_query_swallows_errors_and_returns_empty(self, fake_neo4j_service):
        """Callers treat [] as 'no data'; an exception would 500 the endpoint."""

        class _Boom:
            def session(self, **kwargs):
                raise RuntimeError("connection lost")

        fake_neo4j_service.driver = _Boom()
        assert fake_neo4j_service.execute_query("MATCH (n) RETURN n") == []


# =============================================================================
# 2. Relationship types were hardcoded to CONNECTED_TO for every edge
# =============================================================================

class TestRelationshipTypePreserved:
    """USES_PORT / INVOLVED_IN edges were all stored as CONNECTED_TO."""

    @staticmethod
    def _graph():
        return {
            "nodes": [
                {"data": {"id": "ip1", "label": "192.168.1.10", "type": "InternalIP"}},
                {"data": {"id": "ip2", "label": "203.0.113.5", "type": "ExternalIP"}},
                {"data": {"id": "p443", "label": "443", "type": "Port"}},
                {"data": {"id": "atk1", "label": "PortScan", "type": "Attack"}},
            ],
            "edges": [
                {"data": {"id": "e1", "source": "ip1", "target": "ip2",
                          "label": "CONNECTED_TO", "properties": {"port": 443}}},
                {"data": {"id": "e2", "source": "ip1", "target": "p443",
                          "label": "USES_PORT", "properties": {}}},
                {"data": {"id": "e3", "source": "ip2", "target": "atk1",
                          "label": "INVOLVED_IN", "properties": {}}},
            ],
        }

    def _edge_statements(self, recorded_queries):
        return [q for q in recorded_queries if "UNWIND $edges" in q.cypher]

    @pytest.mark.parametrize("use_merge", [True, False])
    def test_each_edge_label_becomes_its_own_relationship_type(
        self, fake_neo4j_service, recorded_queries, use_merge
    ):
        fake_neo4j_service._store_graph_internal(
            self._graph(), graph_id="g1", batch_size=50, use_merge=use_merge
        )

        statements = self._edge_statements(recorded_queries)
        combined = "\n".join(q.cypher for q in statements)

        assert "[r:CONNECTED_TO" in combined
        assert "[r:USES_PORT" in combined
        assert "[r:INVOLVED_IN" in combined
        # Three distinct labels means three grouped statements, not one.
        assert len(statements) == 3

    @pytest.mark.parametrize("use_merge", [True, False])
    def test_edge_properties_are_always_assigned(
        self, fake_neo4j_service, recorded_queries, use_merge
    ):
        """
        The CREATE branch previously omitted `SET r += edge.properties`, so in
        non-merge mode r.port and r.protocol were never stored at all.
        """
        fake_neo4j_service._store_graph_internal(
            self._graph(), graph_id="g1", batch_size=50, use_merge=use_merge
        )

        for q in self._edge_statements(recorded_queries):
            assert "SET r += edge.properties" in q.cypher

    def test_merge_keys_relationship_on_edge_id(self, fake_neo4j_service, recorded_queries):
        """
        Without {id: edge.id}, MERGE collapses every connection between the same
        IP pair into one relationship, overwriting r.port. The port-scan and
        multi-stage templates count DISTINCT r.port, so they silently saw 1.
        """
        fake_neo4j_service._store_graph_internal(
            self._graph(), graph_id="g1", batch_size=50, use_merge=True
        )

        for q in self._edge_statements(recorded_queries):
            assert "{id: edge.id}" in q.cypher

    def test_two_connections_same_pair_different_ports_stay_separate(
        self, fake_neo4j_service, recorded_queries
    ):
        graph = {
            "nodes": [
                {"data": {"id": "ip1", "label": "10.0.0.1", "type": "InternalIP"}},
                {"data": {"id": "ip2", "label": "10.0.0.2", "type": "InternalIP"}},
            ],
            "edges": [
                {"data": {"id": "e1", "source": "ip1", "target": "ip2",
                          "label": "CONNECTED_TO", "properties": {"port": 22}}},
                {"data": {"id": "e2", "source": "ip1", "target": "ip2",
                          "label": "CONNECTED_TO", "properties": {"port": 80}}},
            ],
        }
        fake_neo4j_service._store_graph_internal(
            graph, graph_id="g1", batch_size=50, use_merge=True
        )

        edge_batches = [q.params["edges"] for q in self._edge_statements(recorded_queries)]
        sent = [e for batch in edge_batches for e in batch]

        assert {e["id"] for e in sent} == {"e1", "e2"}
        assert {e["properties"]["port"] for e in sent} == {22, 80}


# =============================================================================
# 3. sanitize_relationship_type guards the one interpolated value in Cypher
# =============================================================================

class TestSanitizeRelationshipType:
    """Relationship type is interpolated, so it must be validated, not trusted."""

    def test_valid_labels_pass_through(self):
        from app.services.neo4j_service import sanitize_relationship_type

        assert sanitize_relationship_type("CONNECTED_TO") == "CONNECTED_TO"
        assert sanitize_relationship_type("USES_PORT") == "USES_PORT"

    def test_lowercase_and_spaces_are_normalised(self):
        from app.services.neo4j_service import sanitize_relationship_type

        assert sanitize_relationship_type("connected to") == "CONNECTED_TO"
        assert sanitize_relationship_type("  uses port  ") == "USES_PORT"

    @pytest.mark.parametrize(
        "hostile",
        [
            "CONNECTED_TO]->() DETACH DELETE n //",
            "A`]->(x) MATCH (y) DELETE y //",
            "REL{prop:1}",
            "'; DROP ALL",
            "1STARTS_WITH_DIGIT",
            "REL-WITH-DASH",
            "",
            None,
        ],
    )
    def test_hostile_or_malformed_labels_fall_back(self, hostile):
        from app.services.neo4j_service import (
            DEFAULT_RELATIONSHIP_TYPE,
            sanitize_relationship_type,
        )

        assert sanitize_relationship_type(hostile) == DEFAULT_RELATIONSHIP_TYPE

    def test_injection_via_edge_label_never_reaches_cypher(
        self, fake_neo4j_service, recorded_queries
    ):
        graph = {
            "nodes": [
                {"data": {"id": "a", "label": "a", "type": "InternalIP"}},
                {"data": {"id": "b", "label": "b", "type": "InternalIP"}},
            ],
            "edges": [
                {"data": {"id": "e1", "source": "a", "target": "b",
                          "label": "X]->() DETACH DELETE n //", "properties": {}}},
            ],
        }
        fake_neo4j_service._store_graph_internal(
            graph, graph_id="g1", batch_size=50, use_merge=True
        )

        combined = "\n".join(q.cypher for q in recorded_queries)
        assert "DETACH DELETE" not in combined
        assert "[r:RELATED_TO" in combined


# =============================================================================
# 4. Anomaly query operator precedence
# =============================================================================

class TestAnomalyQueryPrecedence:
    """
    `WHERE a OR b AND NOT c` binds AND tighter than OR, so Port nodes with
    is_anomaly = true leaked into the IP anomaly results. The OR must be
    parenthesised.
    """

    def test_anomalies_endpoint_parenthesises_the_or(self):
        import re
        from pathlib import Path

        source = Path(
            __import__("app.api.routes.network", fromlist=["x"]).__file__
        ).read_text()

        # Find the anomaly-scoped WHERE clause.
        assert "n.is_anomaly = true OR n.anomaly_score > 0.5" in source
        match = re.search(
            r"WHERE\s*\(\s*n\.is_anomaly = true OR n\.anomaly_score > 0\.5\s*\)",
            source,
        )
        assert match, "the OR in the anomaly filter must be parenthesised"

    def test_port_exclusion_is_still_present(self):
        from pathlib import Path

        source = Path(
            __import__("app.api.routes.network", fromlist=["x"]).__file__
        ).read_text()
        assert "n.type <> 'Port'" in source


# =============================================================================
# 5. GraphMerger returned an id that was never stored
# =============================================================================

class TestGraphMergerIdRoundTrip:
    """
    merge_graphs() minted merged_graph_id but called store_graph(), which
    generates its own UUID and discards it -- so the id handed back to the
    caller matched nothing in Neo4j.
    """

    class _StubNeo4j:
        def __init__(self):
            self.stored_with_id = None
            self.used_plain_store_graph = False

        def get_graph(self, graph_id, **kwargs):
            return {
                "nodes": [
                    {"data": {"id": f"{graph_id}_n1", "label": "192.168.1.10",
                              "type": "InternalIP", "properties": {}}},
                ],
                "edges": [],
            }

        def store_graph_merge(self, graph, graph_id=None, batch_size=50):
            self.stored_with_id = graph_id
            return graph_id

        def store_graph(self, graph, batch_size=50):
            self.used_plain_store_graph = True
            return "some-unrelated-uuid"

    def test_returned_id_is_the_id_that_was_stored(self):
        from app.services.graph_merger import GraphMerger

        stub = self._StubNeo4j()
        result = GraphMerger(stub).merge_graphs("semantic1", "telemetry1", "merged_fixed")

        assert stub.stored_with_id == "merged_fixed"
        assert result["merged_graph_id"] == "merged_fixed"
        assert not stub.used_plain_store_graph

    def test_generated_id_is_also_round_tripped(self):
        from app.services.graph_merger import GraphMerger

        stub = self._StubNeo4j()
        result = GraphMerger(stub).merge_graphs("semantic1", "telemetry1")

        assert result["merged_graph_id"] == stub.stored_with_id
        assert result["merged_graph_id"].startswith("merged_")


# =============================================================================
# 6. The app must import and expose routes without a live database
# =============================================================================

class TestAppImportsWithoutDatabase:
    """
    network.py built a module-level Neo4jService, which ran setup_constraints()
    at import time. That made importing the app require a running Neo4j and
    made every route untestable.
    """

    def test_app_imports_with_no_neo4j(self):
        from app.main import app

        assert app.title

    def test_all_routes_register(self):
        from app.main import app

        # FastAPI wraps included routers lazily, so app.routes no longer
        # flattens them; the OpenAPI schema is the authoritative view.
        paths = app.openapi()["paths"]

        assert "/health" in paths
        assert "/api/network/anomalies/{graph_id}" in paths
        assert "/api/network/detect-scan" in paths
        assert "/api/network/detect-exfiltration" in paths
        assert "/api/query" in paths
        assert len(paths) >= 21

    def test_network_module_has_no_module_level_service(self):
        import app.api.routes.network as network_module

        for name, value in vars(network_module).items():
            assert type(value).__name__ != "Neo4jService", (
                f"{name} is a module-level Neo4jService; use Depends() instead"
            )

    def test_no_endpoint_references_an_undeclared_service(self):
        """
        The real bug: upload_and_process_csv referenced `neo4j_service` in its
        body after the module-level instance was removed, but never declared it
        as a parameter -- so every call raised NameError -> 500. Assert that any
        endpoint touching `neo4j_service` also declares it via Depends().
        """
        import ast
        from pathlib import Path

        import app.api.routes.network as network_module

        tree = ast.parse(Path(network_module.__file__).read_text())

        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            declares = any(
                arg.arg == "neo4j_service"
                for arg in list(node.args.args) + list(node.args.kwonlyargs)
            )
            references = any(
                isinstance(n, ast.Name) and n.id == "neo4j_service"
                for n in ast.walk(node)
            )
            # `references` includes the parameter itself, so only a body use
            # without a declaration is a bug.
            if references and not declares:
                offenders.append(node.name)

        assert not offenders, (
            f"these endpoints use neo4j_service without declaring it: {offenders}"
        )

    def test_db_backed_endpoints_take_the_service_by_dependency(self):
        from app.api.routes.network import router

        # Endpoints that read/write the graph must resolve the service via DI.
        # The two stateless detectors (detect_port_scan / detect_exfiltration)
        # analyse request-body logs only and intentionally take no service.
        stateless = {"detect_port_scanning", "detect_data_exfil"}
        db_routes = [
            r for r in router.routes if r.endpoint.__name__ not in stateless
        ]

        assert db_routes, "expected DB-backed network routes"
        for route in db_routes:
            params = inspect.signature(route.endpoint).parameters
            assert "neo4j_service" in params, (
                f"{route.endpoint.__name__} should take neo4j_service via Depends()"
            )


# =============================================================================
# 7. Configuration must be readable from the environment
# =============================================================================

class TestSettings:
    """cors_origins used pydantic v1's Field(env=...), silently ignored in v2."""

    def test_cors_origins_accepts_comma_separated_env(self, monkeypatch):
        from app.config import Settings

        monkeypatch.setenv("CORS_ORIGINS", "http://a.test,http://b.test")
        settings = Settings(_env_file=None)

        assert settings.cors_origins == ["http://a.test", "http://b.test"]

    def test_cors_origins_accepts_a_real_list(self):
        from app.config import Settings

        settings = Settings(_env_file=None, cors_origins=["http://c.test"])
        assert settings.cors_origins == ["http://c.test"]

    def test_cors_origins_has_a_default(self):
        from app.config import Settings

        assert Settings(_env_file=None).cors_origins == ["http://localhost:3000"]

    def test_log_level_is_normalised(self, monkeypatch):
        from app.config import Settings

        monkeypatch.setenv("LOG_LEVEL", "debug")
        assert Settings(_env_file=None).log_level == "DEBUG"

    def test_invalid_log_level_is_rejected(self, monkeypatch):
        from pydantic import ValidationError

        from app.config import Settings

        monkeypatch.setenv("LOG_LEVEL", "chatty")
        with pytest.raises(ValidationError):
            Settings(_env_file=None)

    def test_credentials_are_not_allowed_with_a_wildcard_origin(self):
        """
        Browsers reject Access-Control-Allow-Credentials alongside origin "*",
        so main.py must not pair them.
        """
        from app.main import app

        cors = [m for m in app.user_middleware if "CORS" in str(m)]
        assert cors, "expected CORS middleware to be installed"

        options = cors[0].kwargs
        if "*" in options.get("allow_origins", []):
            assert options.get("allow_credentials") is False


# =============================================================================
# 8. LLM configuration must come from settings, not os.environ
# =============================================================================

class TestLLMFactoryUsesSettings:
    """
    load_dotenv() is gone -- pydantic-settings reads .env into Settings without
    exporting to os.environ -- so os.environ.get() would miss .env values.
    """

    def test_llm_factory_does_not_read_os_environ(self):
        """No runtime env reads: config must funnel through settings. The
        module may still *mention* os.environ in a comment, so match call
        syntax, not the bare word."""
        import ast
        from pathlib import Path

        import app.services.llm_factory as factory

        tree = ast.parse(Path(factory.__file__).read_text())

        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "os" and node.attr in {"environ", "getenv"}:
                    offenders.append(f"os.{node.attr}")
        assert not offenders, f"llm_factory reads {offenders}; use settings instead"

    def test_groq_reads_key_from_settings(self, monkeypatch):
        from app.services import llm_factory

        monkeypatch.setattr(llm_factory.settings, "groq_api_key", "test-key-123")
        monkeypatch.setattr(llm_factory.settings, "groq_model", "test-model")

        llm = llm_factory.GroqLLM()
        assert llm.api_key == "test-key-123"
        assert llm.model == "test-model"

    def test_missing_groq_key_raises_actionable_error(self, monkeypatch):
        from app.services import llm_factory

        monkeypatch.setattr(llm_factory.settings, "llm_provider", "groq")
        monkeypatch.setattr(llm_factory.settings, "groq_api_key", "")

        with pytest.raises(ValueError, match="GROQ_API_KEY"):
            llm_factory.get_llm()

    def test_unknown_provider_raises(self, monkeypatch):
        from app.services import llm_factory

        monkeypatch.setattr(llm_factory.settings, "llm_provider", "gpt-9")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            llm_factory.get_llm()

    def test_ollama_provider_needs_no_api_key(self, monkeypatch):
        from app.services import llm_factory

        monkeypatch.setattr(llm_factory.settings, "llm_provider", "ollama")
        monkeypatch.setattr(llm_factory.settings, "ollama_model", "llama3")

        llm = llm_factory.get_llm()
        assert isinstance(llm, llm_factory.OllamaLLM)
        assert llm.model == "llama3"


# =============================================================================
# 9. Ephemeral ports are not evidence of compromise
# =============================================================================

class TestEphemeralPortsNotSuspicious:
    """
    `port > 49152 and port not in [49152, 49153]` flagged all 16k dynamic-range
    ports while sparing exactly two, so ordinary traffic scored as malicious.
    """

    def test_known_malware_ports_still_flagged(self):
        from app.services.network_parser import is_suspicious_port

        for port in (4444, 5555, 6666, 7777, 31337, 12345, 54321, 1234):
            assert is_suspicious_port(port), f"{port} should be flagged"

    def test_common_service_ports_not_flagged(self):
        from app.services.network_parser import is_suspicious_port

        for port in (22, 80, 443, 3306, 5432, 8080):
            assert not is_suspicious_port(port), f"{port} should not be flagged"

    @pytest.mark.parametrize("port", [49152, 49153, 50000, 55555, 60000, 65535])
    def test_ephemeral_range_not_flagged(self, port):
        from app.services.network_parser import is_suspicious_port

        assert not is_suspicious_port(port), (
            f"{port} is in the IANA dynamic range and must not be suspicious"
        )

    def test_parser_does_not_mark_ephemeral_destination_suspicious(self):
        from app.services.network_parser import NetworkLogParser

        parser = NetworkLogParser()
        connections = parser.parse_logs([
            {"source_ip": "192.168.1.10", "dest_ip": "203.0.113.5",
             "source_port": 51000, "dest_port": 55000, "protocol": "TCP"},
        ])

        assert connections[0]["is_suspicious_port"] is False

    @pytest.mark.parametrize("port", [50000, 55555, 60000, 65535])
    def test_rule_based_detection_does_not_tag_ephemeral_ports(self, port):
        """
        The same false positive lived a second time in the rule engine, which
        emitted `high_ephemeral_port:<port>` for any TCP/UDP destination above
        49152. Removing it must not cost the genuinely suspicious high ports.
        """
        from app.services.anomaly_detector import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector()
        anomalies = detector._rule_based_detection({
            "dest_port": port,
            "protocol": "TCP",
            "source_is_internal": True,
            "dest_is_internal": False,
            "is_suspicious_port": False,
            "bytes_sent": 1000,
            "timestamp": "2025-06-01 13:00:00",
        })

        assert not any(a.startswith("high_ephemeral_port") for a in anomalies), (
            f"port {port} is an ordinary dynamic-range port: {anomalies}"
        )

    def test_rule_based_detection_still_flags_curated_high_ports(self):
        """31337/54321 sit above 49152-ish territory but are real C2 defaults."""
        from app.services.anomaly_detector import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector()
        for port in (31337, 54321):
            anomalies = detector._rule_based_detection({
                "dest_port": port,
                "protocol": "TCP",
                "source_is_internal": True,
                "dest_is_internal": False,
                # set by the parser from SUSPICIOUS_PORTS
                "is_suspicious_port": True,
                "bytes_sent": 1000,
                "timestamp": "2025-06-01 13:00:00",
            })
            assert any(a.startswith("suspicious_port:") for a in anomalies), (
                f"{port} should still be reported: {anomalies}"
            )


# =============================================================================
# 10. Dead modules stay deleted
# =============================================================================

class TestDeadCodeRemoved:
    """These modules were orphaned document-era code; rag_service also called
    get_llm() at import time, crashing without an API key."""

    @pytest.mark.parametrize(
        "module",
        [
            "app.services.rag_service",
            "app.utils.text_processors",
            "app.utils.errors",
        ],
    )
    def test_module_is_gone(self, module):
        with pytest.raises(ImportError):
            __import__(module)


# =============================================================================
# 11. Cypher templates only read edge properties that are actually stored
# =============================================================================

class TestEdgePropertyContract:
    """
    Four templates summed `COALESCE(r.bytes_sent, 0)`, but neither edge writer
    ever stored a `bytes_sent` property -- both store `bytes` (sent + received
    combined). COALESCE turned the schema mismatch into a silent, permanent 0,
    which was then handed to the LLM as a grounded fact: `TOP_TALKERS` ranked
    traffic volume while reporting every volume as zero.

    These tests pin producer and consumer to each other, so renaming the
    property on either side fails loudly instead of silently zeroing out.
    """

    # Everything the two edge writers put in an edge's `properties` map:
    # network_parser.connections_to_graph and auto_processor's graph builder.
    WRITTEN_EDGE_PROPERTIES = {
        "protocol",
        "port",
        "bytes",
        "timestamp",
        "is_anomaly",
        "is_suspicious",
    }

    def test_writer_stores_bytes_not_bytes_sent(self):
        """The producer side of the contract."""
        from app.services.network_parser import NetworkLogParser

        parser = NetworkLogParser()
        connections = parser.parse_logs([{
            "source_ip": "10.0.0.5", "dest_ip": "8.8.8.8",
            "dest_port": 443, "protocol": "TCP",
            "bytes_sent": 700, "bytes_received": 300,
            "timestamp": "2025-06-01 13:00:00",
        }])
        graph = parser.connections_to_graph(connections)

        conn_edges = [
            e for e in graph["edges"]
            if e["data"]["label"] == "CONNECTED_TO"
        ]
        assert conn_edges, "expected a CONNECTED_TO edge"

        props = conn_edges[0]["data"]["properties"]
        assert "bytes_sent" not in props, (
            "writer now stores bytes_sent; the Cypher templates read r.bytes "
            "and must be updated together"
        )
        assert props["bytes"] == 1000, (
            f"`bytes` should be sent + received, got {props.get('bytes')}"
        )

    def test_no_template_reads_bytes_sent(self):
        """The consumer side: the exact regression."""
        from app.services.cypher_query_service import CYPHER_TEMPLATES

        offenders = [
            intent.value for intent, tpl in CYPHER_TEMPLATES.items()
            if "bytes_sent" in tpl
        ]
        assert not offenders, (
            f"templates read the nonexistent edge property r.bytes_sent: "
            f"{offenders}"
        )

    def test_every_edge_property_read_is_stored(self):
        """
        Generalizes the pin: any `r.<prop>` a template reads must be a property
        some writer actually stores, so the next mismatch fails here rather
        than silently resolving to a COALESCE default.
        """
        from app.services.cypher_query_service import CYPHER_TEMPLATES

        unknown = {}
        for intent, tpl in CYPHER_TEMPLATES.items():
            # `r` is the relationship variable every template binds.
            read = set(re.findall(r"\br\.([a-zA-Z_][a-zA-Z0-9_]*)", tpl))
            missing = read - self.WRITTEN_EDGE_PROPERTIES
            if missing:
                unknown[intent.value] = sorted(missing)

        assert not unknown, (
            f"templates read edge properties no writer stores: {unknown}. "
            f"Stored properties are {sorted(self.WRITTEN_EDGE_PROPERTIES)}."
        )
