# Network Security Graph RAG

A network security analysis system that uses **knowledge graphs** and **RAG (Retrieval-Augmented Generation)** to detect threats and answer security questions with **grounded, explainable answers**.

[![CI](https://github.com/Kushagrakumar12/Network-Security-Graph-RAG/actions/workflows/ci.yml/badge.svg)](https://github.com/Kushagrakumar12/Network-Security-Graph-RAG/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green)
![Neo4j](https://img.shields.io/badge/Neo4j-5.x-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Why This Exists

Traditional log analysis tools let you search. This system lets you **understand**.

| Problem | Solution |
|---------|----------|
| Relational queries fail for "show me IPs that talked to same suspicious destination" | Graph traversal makes this trivial |
| ML anomaly detection gives scores, not explanations | Graph-native detection with full explainability |
| LLM chatbots hallucinate about your data | Cypher-grounded RAG ensures answers come from real query results |

This project combines: **Graph structure + ML detection + Grounded RAG**

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NETWORK SECURITY GRAPH RAG                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────┐     ┌──────────────┐     ┌─────────────────────────────────┐  │
│  │  CSV    │────▶│   Parser     │────▶│         Neo4j Graph             │  │
│  │  Logs   │     │ (Auto-detect)│     │  IPs → Ports → Connections      │  │
│  └─────────┘     └──────────────┘     └─────────────────────────────────┘  │
│                                                     │                       │
│                         ┌───────────────────────────┼───────────────────┐   │
│                         ▼                           ▼                   │   │
│              ┌─────────────────────┐    ┌─────────────────────┐         │   │
│              │  Behavioral         │    │  ML Anomaly          │         │   │
│              │  Detection          │    │  Detection           │         │   │
│              │  • Port Scanners    │    │  • Isolation Forest  │         │   │
│              │  • Recon-to-Exploit │    │  • Statistical       │         │   │
│              │  • Multi-stage      │    │    Outliers          │         │   │
│              └─────────────────────┘    └─────────────────────┘         │   │
│                         │                           │                   │   │
│                         └───────────┬───────────────┘                   │   │
│                                     ▼                                   │   │
│                      ┌─────────────────────────────┐                    │   │
│                      │    Cypher-Grounded RAG      │                    │   │
│                      │  Query → Intent → Template  │                    │   │
│                      │  → Results → LLM Answer     │                    │   │
│                      └─────────────────────────────┘                    │   │
│                                                                         │   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Features

### 1. Data Ingestion (Auto-Detection)
- **UNSW-NB15** — full (~49 column) and preprocessed training/testing splits
- **CICIDS2017** — with or without IP columns
- Format is detected from the header row; no format flag is passed
- Unified `network_security` graph with MERGE semantics (no duplicates)

> **Data fidelity caveat.** The preprocessed UNSW-NB15 splits ship without IP
> addresses, so the loader **synthesizes** them from each row's `id` to make a
> graph possible — connection topology on that format is an artifact of row
> ordering, not real host behaviour. CICIDS2017 byte counts are **always**
> generated randomly, even when the CSV carries real IPs, so volume-based
> results (notably `/api/network/detect-exfiltration`) are not meaningful there.
> Attack labels and flow features stay genuine in both cases. See
> [backend/sample_data/README.md](backend/sample_data/README.md) for the full
> per-format table.

### 2. Behavioral Threat Detection

| Detection Type | What It Finds | Cypher Pattern |
|----------------|---------------|----------------|
| **Port Scanners** | IPs accessing >5 distinct ports | Connection fan-out analysis |
| **Reconnaissance** | Multi-port access patterns | Port diversity ratio |
| **Multi-Stage Attackers** | High ports AND high volume | Combined AND logic |
| **Recon-to-Exploit** | Broad scan + focused targeting | Port concentration ratio ≥0.6 |
| **High Volume** | Connection flooding | Connections >50 threshold |

Each detection is **fully explainable**:
```json
{
  "ip_address": "59.166.0.7",
  "ports_accessed": 10,
  "total_connections": 11,
  "severity": "High",
  "anomaly_type": "Multi-port Access",
  "threat_pattern": "Recon-to-Exploit"
}
```

### 3. Cypher-Grounded RAG

**Not free-form LLM generation.** The system uses template-constrained Cypher:

1. LLM classifies query intent + extracts entities
2. Intent maps to a static, parameterized Cypher template
3. Query executes against Neo4j — user input only ever arrives as a bound `$parameter`
4. LLM answers **only from actual results**

**Supported intents** (13 total, defined in `QueryIntent`):

| Intent | Purpose |
|---|---|
| `attacks_detected` | Behavioral threat inference |
| `ip_connections` | Connections for a specific IP |
| `anomalies` | Behavioral anomaly detection |
| `top_talkers` | Most active IPs |
| `port_analysis` | Activity for a given port |
| `network_topology` | Node/relationship overview |
| `attack_details` | Detail for a named attack type |
| `suspicious_ips` | Pattern-based suspicious IPs |
| `protocol_analysis` | Traffic broken down by protocol |
| `port_scanners` | Port scanning detection |
| `multi_stage_attackers` | Combined attack patterns |
| `exploit_preparation` | Recon-to-exploit detection |
| `general` | Fallback summary |

## Quick Start

### Prerequisites
- Docker & Docker Compose (v2.24+ — the compose file uses the long-form `env_file` syntax)
- Groq API key (free tier at [console.groq.com](https://console.groq.com))

### Installation

```bash
git clone https://github.com/Kushagrakumar12/Network-Security-Graph-RAG.git
cd Network-Security-Graph-RAG

# Configure environment (note: backend/, not the repo root)
cp backend/.env.example backend/.env
# Edit backend/.env and add your GROQ_API_KEY

# Start services
docker compose up -d

# Verify
curl http://localhost:8000/health
```

The stack still starts without `backend/.env` — Neo4j comes up and ingestion
works, but RAG queries return a clear configuration error until `GROQ_API_KEY`
is set.

### Local development

Use the dev overlay for a source bind-mount, hot reload and debug logging:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

To run the API directly against a local Neo4j, set
`NEO4J_URI=bolt://localhost:7687` in `backend/.env`, then:

```bash
cd backend
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

### Upload Data

```bash
# Upload CSV (auto-detects format)
curl -X POST http://localhost:8000/api/network/upload-csv \
  -F "file=@UNSW_NB15_training-set.csv"
```

You can also drop CSVs into `backend/sample_data/` and restart — they are
ingested on startup unless `ENABLE_AUTO_PROCESS=false`.

### Query the Graph

**Using the dedicated network query endpoint (recommended):**
```bash
curl -X POST http://localhost:8000/api/network/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What attacks were detected?"}'
```

**Example Queries:**
```json
{"query": "Show me port scanning activity"}
{"query": "Which IPs are suspicious?"}
{"query": "What anomalies were detected in the network?"}
{"query": "Which IPs show both port scanning and high connection volume?"}
```

**Sample Response:**
```json
{
  "answer": "Two types of attacks were detected: Reconnaissance (13 IPs including 59.166.0.0) and High Volume Traffic (10 IPs including 149.171.126.8).",
  "intent": "attacks_detected",
  "confidence_score": 0.9,
  "query_results_count": 2,
  "grounding_context": "Results from Neo4j: ..."
}
```

## API Reference

21 endpoints. Interactive docs at `http://localhost:8000/api/docs`.

### Ingestion

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/network/upload-csv` | POST | Upload a CSV; format auto-detected (`max_rows`, default 5000) |
| `/api/network/ingest` | POST | Ingest structured logs from a JSON body |
| `/api/network/process-logs` | POST | Parse raw log lines with auto-detection |
| `/api/network/merge-graphs` | POST | Merge multiple graphs into one |

### Analysis & detection

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/network/query` | POST | Grounded RAG query (recommended) |
| `/api/network/analyze/{graph_id}` | GET | Full security analysis |
| `/api/network/anomalies/{graph_id}` | GET | Anomaly report |
| `/api/network/stats/{graph_id}` | GET | Network statistics |
| `/api/network/summary/{graph_id}` | GET | Security summary |
| `/api/network/correlations/{graph_id}` | GET | Correlated attack patterns |
| `/api/network/connections/{ip}` | GET | Connections for one IP |
| `/api/network/detect-scan` | POST | Port-scan detection on posted logs |
| `/api/network/detect-exfiltration` | POST | Data-exfiltration detection on posted logs |

`detect-scan` and `detect-exfiltration` are stateless — they analyze the logs in
the request body and do not read from Neo4j.

### Graph management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/graphs` | GET | List all graphs |
| `/api/graphs/{graph_id}` | GET | Get a specific graph |
| `/api/graphs/{graph_id}/filter` | POST | Filter a graph's nodes/edges |
| `/api/query` | POST | Generic RAG query |
| `/api/network/graphs` | GET | List network graphs |
| `/api/network/cleanup` | DELETE | Remove old graphs (keeps `network_security`) |
| `/api/network/reset` | DELETE | Delete all graphs |
| `/health` | GET | Health check (used by the container healthcheck) |

## Configuration

All settings live in `backend/.env` (copy from `backend/.env.example`). The file
is gitignored — never commit real credentials.

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key; required when `LLM_PROVIDER=groq` | — |
| `LLM_PROVIDER` | `groq` or `ollama` | `groq` |
| `GROQ_MODEL` | Groq model name | `llama-3.3-70b-versatile` |
| `OLLAMA_BASE_URL` | Ollama endpoint (when `LLM_PROVIDER=ollama`) | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama model name | `llama3` |
| `NEO4J_URI` | Neo4j bolt URI | `bolt://neo4j:7687` |
| `NEO4J_USER` / `NEO4J_PASSWORD` | Neo4j credentials | `neo4j` / `password` |
| `NEO4J_AUTH` | Compose-only; must match the two above | `neo4j/password` |
| `ENABLE_AUTO_PROCESS` | Ingest `backend/sample_data/*.csv` on startup | `true` |
| `CORS_ORIGINS` | Comma-separated list or JSON array; `*` allowed | `http://localhost:3000` |
| `API_PREFIX` | Prefix for all API routes | `/api` |
| `DEBUG` / `LOG_LEVEL` | Debug mode and log verbosity | `false` / `INFO` |

Credentials are automatically disabled when `CORS_ORIGINS` contains `*`, since
browsers reject that combination.

## Project Structure

```
Network-Security-Graph-RAG/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── dependencies.py           # Shared Neo4j driver injection
│   │   │   └── routes/
│   │   │       ├── network.py            # Network security endpoints
│   │   │       ├── query.py              # RAG query endpoints
│   │   │       └── graph.py              # Graph operations
│   │   ├── services/
│   │   │   ├── neo4j_service.py          # Neo4j operations
│   │   │   ├── cypher_query_service.py   # Grounded RAG
│   │   │   ├── auto_processor.py         # CSV format detection + ingest
│   │   │   ├── anomaly_detector.py       # ML detection
│   │   │   ├── network_parser.py         # Log parsing
│   │   │   ├── graph_merger.py           # Graph merge logic
│   │   │   └── llm_factory.py            # Groq / Ollama client
│   │   ├── models/                       # Pydantic models
│   │   ├── deprecated/                   # Archived document-RAG code (not imported)
│   │   ├── config.py                     # Settings (reads backend/.env)
│   │   └── main.py                       # App factory + lifespan
│   ├── sample_data/                      # Drop CSVs here (datasets gitignored)
│   ├── tests/
│   ├── pytest.ini
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── .env.example
├── docker/
│   └── backend.Dockerfile
├── docs/
│   ├── TECHNICAL_REFERENCE.md
│   ├── CASE_STUDY.md
│   └── CYPHER_QUERIES.md
├── docker-compose.yml
├── docker-compose.dev.yml
├── CODEBASE.md
├── LICENSE
└── README.md
```

`backend/app/deprecated/` holds an earlier document-RAG implementation. It is
kept for reference, is not imported by the running app, and its dependencies
(langchain, PyPDF2, ...) are **not** in `requirements.txt` — install them
manually if you revive that code.

## Documentation

- [CODEBASE.md](CODEBASE.md) — module-by-module tour
- [docs/TECHNICAL_REFERENCE.md](docs/TECHNICAL_REFERENCE.md) — services, models, data flow
- [docs/CYPHER_QUERIES.md](docs/CYPHER_QUERIES.md) — the graph schema and query templates
- [docs/CASE_STUDY.md](docs/CASE_STUDY.md) — design rationale and results
- [backend/sample_data/README.md](backend/sample_data/README.md) — datasets and fidelity caveats

## Limitations (Honest Assessment)

### What This System Cannot Do

| Limitation | Reason |
|------------|--------|
| **Encrypted traffic analysis** | Only metadata (IPs, ports, bytes) is analyzed |
| **Real-time streaming** | Batch processing only |
| **Dataset generalization** | Tested on UNSW-NB15/CICIDS2017 |
| **Novel attack detection** | No zero-day capability |
| **Trustworthy topology on some formats** | Preprocessed UNSW-NB15 IPs and CICIDS2017 byte counts are synthesized (see above) |

### What This Is NOT

- ❌ A replacement for a SIEM
- ❌ Real-time threat detection
- ❌ Production SOC-ready (without hardening)
- ❌ Trained on your specific network baseline

### What This IS

- ✅ Graph-based network analysis
- ✅ Behavioral pattern detection
- ✅ Explainable threat detection
- ✅ Grounded RAG (no hallucination)
- ✅ Educational/research tool

## Why Graph Database?

| Query Type | Log Search | SQL | **Graph** |
|------------|-----------|-----|-----------|
| "IP scanned 50 ports?" | ✅ Easy | ✅ Easy | ✅ Easy |
| "IP talked to 3 IPs that hit same C2?" | ❌ Hard | ⚠️ Complex joins | ✅ Single traversal |
| "Attack chain visualization?" | ❌ No | ❌ Complex | ✅ Native |

## Tech Stack

- **FastAPI** — async Python API framework
- **Neo4j** — native graph database
- **Groq** — fast LLM inference (Llama 3.3 70B), with Ollama as a local fallback
- **scikit-learn** — Isolation Forest for ML anomaly detection
- **Docker** — containerization

## Testing

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

The default run needs no database: `pytest.ini` deselects the `integration`
marker. To include tests that require a live Neo4j:

```bash
pytest -m integration
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- UNSW-NB15 dataset: [UNSW Sydney](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- CICIDS2017 dataset: [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
