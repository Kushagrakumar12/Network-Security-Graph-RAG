# Network Security Graph RAG: Complete Technical Reference

> **A-to-Z documentation covering every algorithm, service, and endpoint with code verification**

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Algorithms (Verified in Code)](#algorithms-verified-in-code)
4. [Services](#services)
5. [API Endpoints](#api-endpoints)
6. [Data Flow](#data-flow)
7. [Schema Design](#schema-design)
8. [Configuration](#configuration)
9. [Testing](#testing)

---

## Project Overview

**Purpose**: A security analysis system that:
- Ingests network logs (CSV or JSON)
- Builds knowledge graphs in Neo4j
- Detects anomalies using ML + graph-native algorithms
- Answers natural language queries with grounded RAG

**Tech Stack**:
| Component | Technology |
|-----------|------------|
| API Framework | FastAPI |
| Graph Database | Neo4j 5.x |
| LLM Provider | Groq (Llama 3.3 70B), Ollama fallback |
| ML Library | scikit-learn |
| Containerization | Docker Compose |

> Text/URL/document ingestion was part of an earlier iteration and now lives,
> unwired, in `backend/app/deprecated/`. This reference covers the network
> telemetry pipeline that the running app actually exposes.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ CSV Upload  │  │ JSON Log    │  │ Natural Language Query  │ │
│  │ Endpoint    │  │ Ingest      │  │ Endpoint                │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────────────────────┐  ┌─────────────────────────┐  │
│  │      Network Parser         │  │ Cypher Query Service    │  │
│  │  (format auto-detection)    │  │ (Template-constrained)  │  │
│  └──────────────┬──────────────┘  └───────────┬─────────────┘  │
│                 │                              │               │
│                 ▼                              │               │
│  ┌─────────────────────────────┐               │               │
│  │      Anomaly Detector       │               │               │
│  │      (ML + Rules)           │               │               │
│  └──────────────┬──────────────┘               │               │
│                 │                              │               │
│                 ▼                              ▼               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      Neo4j Graph Database                   ││
│  │  - Nodes: IP, Port, Attack, Protocol                        ││
│  │  - Edges: one relationship type per edge label              ││
│  └─────────────────────────────────────────────────────────────┘│
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 Graph Anomaly Detector                      ││
│  │  - Degree Spike    - Fan-Out Detection                      ││
│  │  - Protocol Rarity - Suspicious Port Access                 ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Algorithms (Verified in Code)

### 1. Isolation Forest (ML-based Anomaly Detection)

**File**: `backend/app/services/anomaly_detector.py`
**Line**: 15, 41

```python
from sklearn.ensemble import IsolationForest

self.model = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42
)
```

**What it detects**: Statistical outliers in feature vectors
**Features used** (`extract_features`, line 48):
- bytes_sent, bytes_received
- duration
- port rarity (`_port_rarity_score`, line 88)
- is_suspicious_port flag
- time-of-day score (`_time_score`, line 100)

sklearn is imported defensively; if it is unavailable the detector falls back to
rules only.

---

### 2. Degree Spike Detection (Graph-native)

**File**: `backend/app/services/graph_anomaly_detector.py`
**Line**: 108

```python
def detect_degree_spikes(self, graph_id: str) -> List[GraphAnomalyResult]:
    # Per-graph baseline: mean + 2σ, computed from this graph's own degrees
    threshold = mean_degree + (2 * std_dev)
    if degree > threshold and degree > 5:   # absolute floor of 5 connections
```

**What it detects**: IPs with unusually high connection counts
**Threshold**: `mean + (2 * std_dev)`, **and** an absolute floor of >5
connections so tiny graphs don't flag everything
**Explainability output**:
```json
{
  "anomaly_type": "degree_spike",
  "baseline": 22.7,
  "observed": 254,
  "confidence_score": 0.785,
  "reason": "IP has 254 connections, significantly above average of 22.7"
}
```

---

### 3. Fan-Out Detection (Port Scanning)

**File**: `backend/app/services/graph_anomaly_detector.py`
**Line**: 168

```python
def detect_fan_out(self, graph_id: str) -> List[GraphAnomalyResult]:
    # Single source IP -> many destination ports
    # Cypher: WHERE size(ports) > 5
```

**What it detects**: One IP connecting to many distinct ports
**Threshold**: more than 5 unique ports
**Severity tiers**: >50 unique ports is the highest band, >20 the next
**Output type**: `fan_out_port_scan`

---

### 4. Protocol Rarity Detection

**File**: `backend/app/services/graph_anomaly_detector.py`
**Line**: 228

```python
def detect_protocol_rarity(self, graph_id: str) -> List[GraphAnomalyResult]:
    if percentage < 1.0 and usage < 10:
```

**What it detects**: Rare protocols that may be covert channels
**Threshold**: under 1% of traffic **and** fewer than 10 connections in absolute
terms — the second condition stops a large graph's 0.9% slice (which can still
be thousands of flows) from being reported as rare
**Output example**:
```json
{
  "anomaly_type": "rare_protocol",
  "entity": "ICMP",
  "observed": "0.34% (2 connections)",
  "reason": "Protocol 'ICMP' used in only 0.34% of connections - may indicate covert channel"
}
```

---

### 5. Suspicious Port Access Detection

**File**: `backend/app/services/graph_anomaly_detector.py` (line 285)
**File**: `backend/app/services/network_parser.py` (lines 54, 68)

```python
SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 31337, 12345, 54321, 1234]

def is_suspicious_port(port: int) -> bool:
    return port in SUSPICIOUS_PORTS
```

**What it detects**: Connections to known malware/backdoor/C2 ports
**Ports monitored**: 4444 (Metasploit/Meterpreter default), 31337 (Back
Orifice), 5555, 6666, 7777, 12345, 54321, 1234

Membership in this curated list is the **only** thing that counts. Sitting in
the IANA dynamic range (49152–65535) is deliberately not treated as suspicious:
that range holds ordinary client source ports and many legitimate high-port
services, so flagging it marked most normal traffic as malicious and inflated
every downstream anomaly score.

---

### 6. Rule-Based Anomaly Detection

**File**: `backend/app/services/anomaly_detector.py`
**Line**: 201

```python
def _rule_based_detection(self, conn: Dict[str, Any]) -> List[str]:
    # Emits tags carrying the offending value:
    # - "suspicious_port:4444"                  (from SUSPICIOUS_PORTS)
    # - "known_malware_port:4444"               (internal -> external only)
    # - "large_external_transfer:15000000bytes" (>10MB outbound)
    # - "unusual_time:score=0.85"               (time score > 0.7)
```

**Features**:
- Port-specific anomaly tagging — note each tag carries its value after a colon,
  so consumers must match on the prefix, not the bare name
- Data exfiltration detection (>10MB outbound, internal→external)
- After-hours activity detection
- `known_malware_port` and `large_external_transfer` are gated on the
  internal→external direction

---

## Services

### 1. NetworkLogParser
**File**: `backend/app/services/network_parser.py`

- Parses CSV/JSON network logs
- Normalizes IP addresses and ports
- Flags suspicious ports
- Detects internal vs external IPs
- `detect_port_scan()` / `detect_data_exfiltration()` operate on a log list

### 2. NetworkAnomalyDetector
**File**: `backend/app/services/anomaly_detector.py`

- Combines Isolation Forest ML with rule-based detection
- Returns anomaly scores (0–1) and anomaly type tags
- `analyze_network_traffic()` is the module-level entry point

### 3. GraphAnomalyDetector
**File**: `backend/app/services/graph_anomaly_detector.py`

- Runs graph-native algorithms against Neo4j
- Degree spike, fan-out, protocol rarity, suspicious ports
- Returns explainable `GraphAnomalyResult` objects
- `analyze_graph_anomalies()` is the entry point

### 4. CypherQueryService
**File**: `backend/app/services/cypher_query_service.py`

- Template-constrained Cypher: the LLM classifies, it never writes queries
- **13** query intents, each with a pre-written template
- Anti-hallucination by design

**Supported intents** (`QueryIntent`, line 19 — defined in this module, not in
`models/network_models.py`):
```python
class QueryIntent(Enum):
    ATTACKS_DETECTED      = "attacks_detected"
    IP_CONNECTIONS        = "ip_connections"
    ANOMALIES             = "anomalies"
    TOP_TALKERS           = "top_talkers"
    PORT_ANALYSIS         = "port_analysis"
    NETWORK_TOPOLOGY      = "network_topology"
    ATTACK_DETAILS        = "attack_details"
    SUSPICIOUS_IPS        = "suspicious_ips"
    PROTOCOL_ANALYSIS     = "protocol_analysis"
    GENERAL               = "general"
    PORT_SCANNERS         = "port_scanners"
    MULTI_STAGE_ATTACKERS = "multi_stage_attackers"
    EXPLOIT_PREPARATION   = "exploit_preparation"
```

**Confidence gating** (lines 479–481). Classification confidence routes the
request into one of three bands:

| Band | Threshold | Behaviour |
|---|---|---|
| Proceed | `>= 0.75` (`CONFIDENCE_PROCEED`) | Answer normally |
| Warn | `>= 0.5` and `< 0.75` | Answer, but flag low confidence |
| Clarify | `< 0.5` (`CONFIDENCE_CLARIFY`) | Ask the user to rephrase instead of guessing |

Two extra safeguards:
- **Vague-query capping** — questions matching `VAGUE_QUERY_PATTERNS` (line 71)
  have confidence capped at 0.6 regardless of what the LLM claims, so an
  over-confident classification of "tell me everything" still lands in the warn
  band.
- **Entity pre-validation** — extracted entities are checked against the graph
  via `neo4j_service.validate_entities()` before the template runs, so a query
  about an IP that does not exist reports that instead of returning an empty
  result set as though it were a finding.

### 5. GraphMerger
**File**: `backend/app/services/graph_merger.py`

- Merges graphs into a single target graph id
- Node-key normalization so the same IP from two datasets becomes one node
- Source provenance tracking
- Cross-correlation detection (`find_correlations`)

### 6. Neo4jService
**File**: `backend/app/services/neo4j_service.py`

- Graph storage and retrieval, index/constraint management
- `execute_query()` runs a template's Cypher with bound parameters
- Writes **one relationship type per edge label**: edges are grouped by type and
  the type is validated by `sanitize_relationship_type()` against
  `^[A-Z][A-Z0-9_]*$` (falling back to `RELATED_TO`) before interpolation, since
  Cypher has no portable dynamic relationship type
- Both the MERGE and CREATE paths assign `r += edge.properties`, and MERGE keys
  on the edge id so two connections between the same pair keep distinct ports

### 7. LLM factory
**File**: `backend/app/services/llm_factory.py`

- `get_llm()` returns a Groq or Ollama client based on `LLM_PROVIDER`
- Reads configuration through `app.config.settings` rather than `os.environ`,
  because pydantic-settings populates the settings object without exporting
  `.env` into the process environment
- Raises an actionable error when `GROQ_API_KEY` is missing

---

## API Endpoints

21 endpoints, all under `API_PREFIX` (default `/api`) except `/health`.

### Data Ingestion

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/upload-csv` | POST | Upload CSV network logs (format auto-detected) |
| `/api/network/ingest` | POST | Ingest JSON network logs |
| `/api/network/process-logs` | POST | Parse raw log lines through the full pipeline |

### Analysis

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/analyze/{graph_id}` | GET | Full security analysis |
| `/api/network/anomalies/{graph_id}` | GET | Anomaly report |
| `/api/network/stats/{graph_id}` | GET | Network statistics |
| `/api/network/summary/{graph_id}` | GET | Human-readable security summary |
| `/api/network/connections/{ip}` | GET | Connections for one IP |

### Detection

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/detect-scan` | POST | Port scan detection (stateless) |
| `/api/network/detect-exfiltration` | POST | Data exfiltration detection (stateless) |

Both read only the posted logs and take no Neo4j dependency.

### Query

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/query` | POST | Grounded RAG query over the network graph |
| `/api/query` | POST | Generic RAG query |

### Graph Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/graphs` | GET | List all graphs |
| `/api/graphs/{graph_id}` | GET | Get one graph |
| `/api/graphs/{graph_id}/filter` | POST | Filter a graph's nodes/edges |
| `/api/network/graphs` | GET | List network graphs |
| `/api/network/merge-graphs` | POST | Merge graphs |
| `/api/network/correlations/{graph_id}` | GET | Find cross-graph correlations |
| `/api/network/cleanup` | DELETE | Remove old graphs (keeps `network_security`) |
| `/api/network/reset` | DELETE | Delete all graphs |

### Health

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Liveness probe (used by the container healthcheck) |

---

## Data Flow

### CSV Ingestion Flow

```
CSV File
    ↓
detect_dataset_format()  →  convert_csv_to_logs()
    ↓
NetworkLogParser.parse_logs()
    ↓
NetworkAnomalyDetector.predict()
    ↓ (ML + rule-based anomalies)
connections_to_graph()
    ↓ (build nodes + edges)
Neo4jService.store_graph_merge()
    ↓
GraphAnomalyDetector.detect_all()
    ↓ (graph-native anomalies)
Final Graph with Anomaly Scores
```

### Query Flow

```
Natural Language Query
    ↓
CypherQueryService.classify_intent()
    ↓ (LLM returns intent + entities + confidence)
confidence gate  →  clarify if < 0.5
    ↓
neo4j_service.validate_entities()
    ↓ (report unknown IPs/ports rather than returning empty results)
CYPHER_TEMPLATES[intent]  +  bound $params
    ↓
Neo4jService.execute_query()
    ↓
LLM answer generation, grounded in the returned rows
    ↓
Final Answer + Context + confidence metadata
```

---

## Schema Design

### Node label vs. node type

Every node is stored under the **single Neo4j label `:Node`**, with its kind held
in a `type` **property**. Templates therefore match `(n:Node)` and filter on
`n.type`, rather than matching distinct labels:

```cypher
MATCH (n:Node {graph_id: $graph_id})
WHERE n.type <> 'Port'
```

Node types written by the telemetry pipeline:

| `type` value | Meaning | Written by |
|---|---|---|
| `InternalIP` | RFC1918 / internal address | `network_parser.py:216`, `auto_processor.py:724` |
| `ExternalIP` | Public address | same |
| `Port` | Destination port | `network_parser.py:232`, `auto_processor.py:747` |
| `AttackType` | Labelled attack class from the dataset | `auto_processor.py:769` |

Because `type` is a property rather than a label, IP-level reports have to
exclude `Port` nodes explicitly. The `/api/network/anomalies/{graph_id}` query
(`api/routes/network.py:111`) does so, and parenthesises its `OR`:

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
WHERE (n.is_anomaly = true OR n.anomaly_score > 0.5)
  AND n.type <> 'Port'
```

The parentheses are load-bearing: Cypher binds `AND` tighter than `OR`, so
without them the `is_anomaly = true` branch stands alone and Port nodes leak into
an IP-level report.

The `anomalies` **query template** (`cypher_query_service.py`) takes a different
route to the same end — it selects IP nodes by dotted-quad label pattern, which
excludes Port nodes implicitly.

### Edge Types

Relationship types come from each edge's own `label`, validated against
`^[A-Z][A-Z0-9_]*$` by `sanitize_relationship_type()`
(`neo4j_service.py:19`, pattern at line 15); anything failing validation becomes
`RELATED_TO`. The pipeline currently emits two:

| Type | Meaning |
|---|---|
| `CONNECTED_TO` | Source IP → destination IP |
| `USES_PORT` | Connection → destination port |

Because the type is derived from the data rather than hardcoded, adding a new
edge label in the parser produces a new relationship type with no storage
change.

### Key Properties

**On nodes**:
- `type`: node kind (see table above)
- `graph_id`: which ingest the node belongs to
- `is_anomaly`: boolean
- `anomaly_score`: 0.0–1.0
- `anomaly_types`: list of strings

---

## Configuration

All settings live in `backend/.env` — copy `backend/.env.example`. The path is
anchored to the `backend/` directory, so config resolves identically whether
uvicorn starts from the repo root, from `backend/`, or from `/app` in Docker.

```env
# Neo4j
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

# LLM
LLM_PROVIDER=groq
GROQ_API_KEY=your_api_key
GROQ_MODEL=llama-3.3-70b-versatile

# CORS: comma-separated or a JSON array
CORS_ORIGINS=http://localhost:3000,http://localhost:8080
```

`CORS_ORIGINS` accepts both spellings. The field is annotated `NoDecode` so
pydantic-settings does not attempt `json.loads()` on the raw value before the
validator runs — without that, a comma-separated value raises `SettingsError`
and the app dies at startup.

### Docker Compose

```yaml
services:
  backend:
    build:
      context: ./backend
      dockerfile: ../docker/backend.Dockerfile
    ports:
      - "8000:8000"
    depends_on:
      neo4j:
        condition: service_healthy
    env_file:
      - path: ./backend/.env
        required: false
```

The long-form `env_file` syntax needs Compose v2.24+. `required: false` lets the
stack boot on a fresh clone before any `.env` exists. For hot reload:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

---

## Testing

### Test Files

- `backend/tests/conftest.py` — fake driver/session fixtures that record every
  Cypher statement, so the storage layer is testable without a database
- `backend/tests/test_sanity.py` — quick sanity checks
- `backend/tests/test_comprehensive.py` — broader feature coverage
- `backend/tests/test_regressions.py` — pins every previously-fixed defect

### Running Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

`pytest.ini` deselects the `integration` marker, so the default run needs no
Neo4j. Use `pytest -m integration` for database-backed tests, or run inside the
stack:

```bash
docker compose exec backend pytest
```

### Test Coverage

- Network parsing: IP normalization, port classification
- ML anomaly detection: Isolation Forest training/prediction, rule tags
- Graph anomaly detection: degree spike, fan-out, protocol rarity
- Cypher service: template staticness, parameter binding, injection prevention
- Storage: relationship typing, MERGE keys, property assignment
- Config: all `CORS_ORIGINS` spellings, log-level validation
- Wiring: app imports without a database, dependency injection completeness

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/Kushagrakumar12/Network-Security-Graph-RAG.git
cd Network-Security-Graph-RAG
cp backend/.env.example backend/.env   # add your Groq API key

# 2. Start services
docker compose up -d

# 3. Swagger UI
open http://localhost:8000/api/docs

# 4. Upload network data
curl -X POST http://localhost:8000/api/network/upload-csv -F "file=@your_data.csv"

# 5. Query the graph
curl -X POST http://localhost:8000/api/network/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What anomalies were detected?"}'
```

---

## Algorithm Verification Summary

| Claimed Algorithm | Location | Line | Status |
|-------------------|----------|------|--------|
| Isolation Forest | `anomaly_detector.py` | 15, 41 | ✅ Verified |
| Rule-based detection | `anomaly_detector.py` | 201 | ✅ Verified |
| Degree Spike (mean+2σ, floor 5) | `graph_anomaly_detector.py` | 108 | ✅ Verified |
| Fan-Out (>5 ports) | `graph_anomaly_detector.py` | 168 | ✅ Verified |
| Protocol Rarity (<1% and <10 uses) | `graph_anomaly_detector.py` | 228 | ✅ Verified |
| Suspicious Ports (curated list of 8) | `graph_anomaly_detector.py` + `network_parser.py` | 285, 54 | ✅ Verified |
| Cypher Templates (13 intents) | `cypher_query_service.py` | 19, 87 | ✅ Verified |
| Confidence gating (3 bands) | `cypher_query_service.py` | 479–481 | ✅ Verified |
| Relationship-type sanitization | `neo4j_service.py` | 15, 19 | ✅ Verified |

---

*Last updated: August 2026 — claims re-verified against the codebase.*
