# Codebase Documentation

A complete breakdown of all files and what they do.

---

## Project Overview

This is a **Network Security Analyzer** that:
1. Takes network traffic data (CSV files or JSON logs)
2. Builds a knowledge graph in Neo4j (IPs, ports, connections)
3. Detects anomalies using ML (Isolation Forest) and graph structure
4. Answers security questions using grounded RAG

---

## Directory Structure

```
Network-Security-Graph-RAG/
├── backend/
│   ├── app/
│   │   ├── api/              # API endpoints + shared dependencies
│   │   ├── models/           # Data models (Pydantic)
│   │   ├── services/         # Business logic
│   │   ├── utils/            # Helper functions
│   │   ├── deprecated/       # Archived document-RAG code (not imported)
│   │   ├── config.py         # Settings
│   │   └── main.py           # App entry point
│   ├── sample_data/          # Drop CSVs here for auto-processing
│   ├── tests/                # Unit + regression tests
│   ├── pytest.ini            # Test config (deselects integration by default)
│   ├── requirements.txt      # Runtime dependencies
│   ├── requirements-dev.txt  # Runtime + test dependencies
│   └── .env.example          # Environment variable template
├── docker/backend.Dockerfile # Backend image
├── docker-compose.yml        # Production-oriented stack
├── docker-compose.dev.yml    # Dev overlay (bind-mount + hot reload)
├── docs/                     # Technical reference, case study, Cypher guide
└── README.md                 # Quick start guide
```

---

## Core Files Explained

### Entry Point

**`backend/app/main.py`**
- Creates the FastAPI app
- Sets up CORS middleware (credentials auto-disabled when origins contain `*`)
- Registers **3 API routers**: graph, query, network
- Manages the Neo4j driver through a `lifespan` context manager
- **Auto-processes CSVs** on startup from `sample_data/` (unless `ENABLE_AUTO_PROCESS=false`)

**`backend/app/config.py`**
- Loads settings from environment variables and `backend/.env`
- The `.env` path is anchored to `backend/`, so config resolves the same way
  regardless of the working directory uvicorn is started from
- Configures: Neo4j connection, LLM provider (Groq/Ollama), CORS, ingestion limits
- Default LLM: Groq with `llama-3.3-70b-versatile`

**`backend/app/api/dependencies.py`**
- Holds the single shared `Neo4jService` instance behind `get_neo4j_service()`
- Endpoints receive it via `Depends()` rather than constructing their own, so the
  app owns exactly one driver connection pool and imports cleanly without a
  running database
- `close_neo4j_service()` is called on shutdown

---

## Services (Business Logic)

### `services/auto_processor.py`
**Purpose**: Automatically detects and processes CSV files

What it does:
- **Detects dataset format** (UNSW-NB15, UNSW-NB15 preprocessed, CICIDS2017)
- **Converts to standard log format** with source/dest IPs, ports, bytes, protocol
- **Runs full pipeline**: parse → detect anomalies → build graph → store in Neo4j
- **Tracks processed files** in `.processed_files` so restarts don't re-ingest

Key functions:
- `detect_dataset_format()` - Figures out what kind of CSV you have
- `convert_csv_to_logs()` - Converts any supported format to the standard shape
- `scan_and_process_csv_files()` - Called on startup to process new files

> Note: the preprocessed UNSW-NB15 and CICIDS2017 paths synthesize some fields.
> See [backend/sample_data/README.md](backend/sample_data/README.md).

---

### `services/network_parser.py`
**Purpose**: Parses network logs into structured connections

What it does:
- Parses raw log entries into connection objects
- Identifies source/destination IPs and ports
- Classifies IPs as internal or external
- Maps port numbers to service names (SSH, HTTP, etc.)
- Converts connections to graph format (nodes + edges)

Key functions:
- `parse_logs()` - Takes raw logs, returns structured connections
- `connections_to_graph()` - Creates Neo4j-ready graph structure
- `detect_port_scan()` - Finds IPs scanning multiple ports
- `detect_data_exfiltration()` - Finds large outbound transfers
- `is_suspicious_port()` - Checks against a curated malware/C2 port list

---

### `services/anomaly_detector.py`
**Purpose**: Detects unusual network activity using ML

What it does:
- Uses **Isolation Forest** to find outliers
- Falls back to rule-based detection if sklearn is unavailable
- Scores connections on port rarity, time of day, bytes transferred
- Flags patterns like unusual hours, suspicious ports, high traffic

Key functions:
- `fit()` / `predict()` - Train and score connections
- `get_summary()` - Human-readable anomaly report
- `analyze_network_traffic()` - Main entry point

---

### `services/neo4j_service.py`
**Purpose**: Stores and queries the knowledge graph

What it does:
- Connects to Neo4j and creates indexes/constraints for fast lookups
- Stores graphs with nodes (IPs, Ports, Attacks) and edges (connections)
- Writes **each edge label as its own relationship type**, grouping edges by
  type and validating the label before it reaches Cypher (Cypher has no
  portable dynamic relationship type)
- Supports **MERGE** to combine multiple datasets into one graph
- Provides filtering and querying capabilities

Key functions:
- `store_graph()` / `store_graph_merge()` - Save graph to database
- `get_graph()` / `list_graphs()` - Retrieve graphs
- `filter_graph()` - Filter by node/edge type or search term
- `execute_query()` - Run a template's Cypher with bound parameters
- `sanitize_relationship_type()` - Validates a label against
  `^[A-Z][A-Z0-9_]*$`, falling back to `RELATED_TO`

---

### `services/cypher_query_service.py`
**Purpose**: Template-constrained Cypher queries with grounded RAG

This is the **primary query system**. It prevents LLM hallucination by:
1. Classifying user intent (not generating raw Cypher)
2. Mapping intent to a static, parameterized Cypher template
3. Grounding LLM answers in actual query results

User input is never concatenated into a query — it arrives only as bound
`$parameters`, and every one of the 13 intents has a template.

Supported intents (13):
`attacks_detected`, `ip_connections`, `anomalies`, `top_talkers`,
`port_analysis`, `network_topology`, `attack_details`, `suspicious_ips`,
`protocol_analysis`, `general`, `port_scanners`, `multi_stage_attackers`,
`exploit_preparation`

Key classes:
- `QueryIntent` - Enum of supported query types (defined in this module)
- `CypherQueryService` - Main service class
- `query_with_grounding()` - Entry point for grounded queries

---

### `services/graph_anomaly_detector.py`
**Purpose**: Graph-native anomaly detection

Works on the graph **structure** (not just per-connection features):

| Detection | What it finds |
|-----------|--------------|
| Degree spike | IP with connections > mean + 2σ |
| Fan-out | Single IP → many ports on same target |
| Protocol rarity | Protocols < 1% of traffic |
| Suspicious ports | Known malware ports (4444, 31337, etc.) |

Each anomaly includes **full explainability**:
```python
{
    "anomaly_type": "degree_spike",
    "entity": "10.0.0.5",
    "confidence_score": 0.87,
    "baseline": 12.3,
    "observed": 47,
    "reason": "IP has 47 connections, above average of 12.3"
}
```

Key classes:
- `GraphAnomalyResult` - Single anomaly with explainability
- `GraphAnomalyDetector` - Main detector class
- `analyze_graph_anomalies()` - Entry point

---

### `services/graph_merger.py`
**Purpose**: Combines separate graphs and surfaces cross-graph correlations

Key members:
- `GraphMerger.merge_graphs()` - Merges graphs into a target graph id,
  normalizing node keys so the same IP from two datasets becomes one node
- `GraphMerger.find_correlations()` - Finds entities appearing across sources
- `merge_semantic_and_telemetry()` - Module-level convenience entry point

---

### `services/llm_factory.py`
**Purpose**: Creates LLM clients (Groq or Ollama)

Supported providers:
- **Groq** (default) - Fast cloud API, uses Llama 3.3 70B
- **Ollama** (fallback) - Local inference, requires Ollama running

Configuration is read through `app.config.settings`, not `os.environ` —
pydantic-settings loads `.env` into the settings object without exporting it to
the process environment, so a raw `os.environ` read would miss `.env` values.

Key function:
- `get_llm()` - Returns a configured client based on `LLM_PROVIDER`, raising an
  actionable error when `GROQ_API_KEY` is missing

---

## API Routes

All routes are mounted under `API_PREFIX` (default `/api`). 21 endpoints total.

### `api/routes/network.py` (Main endpoints)

| Endpoint | What it does |
|----------|--------------|
| `POST /network/upload-csv` | Upload CSV, auto-detect format, process everything |
| `POST /network/ingest` | Ingest JSON logs manually |
| `POST /network/process-logs` | Full pipeline with analysis |
| `POST /network/merge-graphs` | Merge multiple graphs into one |
| `POST /network/query` | Grounded RAG query over the network graph |
| `GET /network/graphs` | List all graph IDs |
| `GET /network/analyze/{id}` | Run all security analyses |
| `GET /network/summary/{id}` | Human-readable security summary |
| `GET /network/anomalies/{id}` | Get anomaly report |
| `GET /network/stats/{id}` | Get network statistics |
| `GET /network/correlations/{id}` | Cross-source correlated patterns |
| `GET /network/connections/{ip}` | Get connections for an IP |
| `POST /network/detect-scan` | Detect port scanning in posted logs |
| `POST /network/detect-exfiltration` | Detect data exfiltration in posted logs |
| `DELETE /network/cleanup` | Remove old graphs (keeps `network_security`) |
| `DELETE /network/reset` | Delete all graphs |

`detect-scan` and `detect-exfiltration` are stateless: they analyze the request
body and take no Neo4j dependency.

---

### `api/routes/query.py`

| Endpoint | What it does |
|----------|--------------|
| `POST /query` | Ask questions in natural language using RAG |

---

### `api/routes/graph.py`

| Endpoint | What it does |
|----------|--------------|
| `GET /graphs` | List all graphs |
| `GET /graphs/{id}` | Get graph data |
| `POST /graphs/{id}/filter` | Filter graph nodes |

---

### `/health`

Registered directly on the app (outside the API prefix) and used by the
container healthcheck.

---

## Data Models

### `models/network_models.py`
- `Protocol`, `AnomalyType` - Enums
- `NetworkLogEntry` - Single log entry with src/dst IP, ports, bytes
- `NetworkLogsInput` - Wrapper for a list of log entries
- `NetworkConnection` - Parsed connection
- `IPNode` - IP-level aggregate
- `AnomalyReport` - Anomaly detection result
- `NetworkGraphResponse` - Graph build response
- `PortScanResult` - Port-scan detection result

### `models/graph.py`
- `NodeData` / `EdgeData` - Payload shapes
- `Node` / `Edge` - Graph primitives
- `GraphResponse` - Complete graph with nodes + edges
- `NodeFilter` - Filter criteria

### `models/query.py`
- `QueryInput` - RAG query with question and optional graph ID
- `QueryResponse` - Answer with context

---

## Utils

### `utils/logging_utils.py`
- Configures logging format and levels

---

## Deprecated

`app/deprecated/` holds the earlier document-RAG implementation
(`document_processor.py`, `graph_extractor.py`, `document_routes.py`,
`document_models.py`). It is **not imported** by the running app, and its
dependencies (langchain, PyPDF2, docx2txt, beautifulsoup4) are **not** in
`requirements.txt`. Install them manually if you revive that code.

---

## Supported Dataset Formats

| Format | Detection Method |
|--------|------------------|
| **UNSW-NB15** | Headerless rows whose first value is an IP (~49 columns), or a `srcip` column |
| **UNSW-NB15 preprocessed** | `id` + `attack_cat` + `label` columns, but no `srcip` |
| **CICIDS2017** | Headers containing `Destination Port` / `Label` |

---

## How the Pipeline Works

1. **Upload CSV** → `upload_and_process_csv()`
2. **Detect Format** → `detect_dataset_format()` figures out what you uploaded
3. **Convert** → `convert_csv_to_logs()` standardizes to our format
4. **Parse** → `NetworkLogParser.parse_logs()` creates connection objects
5. **Detect Anomalies** → `NetworkAnomalyDetector.predict()` scores each connection
6. **Build Graph** → `connections_to_graph()` creates nodes and edges
7. **Store** → `Neo4jService.store_graph_merge()` saves to database
8. **Query** → `CypherQueryService.query_with_grounding()` answers questions

---

## Environment Variables

See the full table in [README.md](README.md#configuration). The essentials:

| Variable | Purpose | Default |
|----------|---------|---------|
| `LLM_PROVIDER` | Which LLM to use | `groq` |
| `GROQ_API_KEY` | Your Groq API key | (required for groq) |
| `GROQ_MODEL` | Model name | `llama-3.3-70b-versatile` |
| `NEO4J_URI` | Database connection | `bolt://neo4j:7687` |
| `NEO4J_USER` | Database user | `neo4j` |
| `NEO4J_PASSWORD` | Database password | `password` |
| `ENABLE_AUTO_PROCESS` | Auto-process CSVs on startup | `true` |
| `CORS_ORIGINS` | Allowed origins (comma-separated or JSON array) | `http://localhost:3000` |

---

## Tests

Located in `backend/tests/`:
- `conftest.py` - Fake Neo4j driver/session fixtures that record Cypher, so the
  storage layer is testable without a database
- `test_sanity.py` - Fast smoke tests
- `test_comprehensive.py` - Broader feature coverage
- `test_regressions.py` - Pins every previously-fixed bug (relationship types,
  MERGE keys, anomaly `WHERE` precedence, CORS parsing, DI wiring, ...)

Run tests:
```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

`pytest.ini` deselects the `integration` marker by default, so a plain `pytest`
run needs no Neo4j. Use `pytest -m integration` for the database-backed tests.
