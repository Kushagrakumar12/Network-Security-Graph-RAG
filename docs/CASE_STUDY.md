# Network Security Graph RAG: Technical Case Study

## Executive Summary

This project implements a **security analysis system** that:
- Ingests network traffic data (CSV, multiple dataset formats auto-detected) and structured JSON logs
- Builds knowledge graphs in Neo4j with graph-native anomaly detection
- Enables natural language security queries via Cypher-grounded RAG
- Merges graphs from separate sources and surfaces cross-source correlations

**Key differentiators:**
- Template-constrained Cypher: user text never reaches a query, so the LLM cannot hallucinate one
- Three-band confidence gating with entity pre-validation before any query runs
- Hybrid detection: Isolation Forest *and* graph-structural rules, each carrying an explainability record
- Honest scope: unimplemented designs are labelled as roadmap, not shipped features

---

## Problem Statement

Traditional security tools have three major limitations:

1. **Siloed data**: Network logs, threat intel, and analyst notes exist separately
2. **No relationship modeling**: Flat logs can't represent attack chains
3. **Query rigidity**: Analysts must know exact queries, can't ask natural questions

### Our Solution

```
Raw Data → Graph Model → Multi-Modal Detection → RAG Interface
   │           │                  │                    │
   │           │                  │                    └─ Natural language queries
   │           │                  └─ ML + Graph-native anomalies
   │           └─ Entities + Relationships in Neo4j
   └─ CSV network logs, Text threat reports, URLs
```

---

## Architecture

### Data Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   CSV Logs   │────▶│   Parser +   │────▶│   Neo4j      │
│ (UNSW/CICIDS)│     │   Anomaly    │     │   Graph      │
└──────────────┘     │   Detector   │     └──────────────┘
                     └──────────────┘            │
┌──────────────┐            ▲                    │
│  JSON logs   │────────────┘                    │
│  (/ingest)   │                                 │
└──────────────┘                                 │
                                                 ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   User       │────▶│   Intent +   │────▶│   Grounded   │
│   Query      │     │   Cypher RAG │     │   Answer     │
└──────────────┘     └──────────────┘     └──────────────┘
```

> An earlier version also ingested threat reports from text and URLs via an LLM
> graph extractor. That code is archived under `backend/app/deprecated/` and is
> not wired into the running app.

### Tech Stack

| Component | Technology | Why |
|-----------|------------|-----|
| API | FastAPI | Async, auto-docs, type safety |
| Graph DB | Neo4j 5.x | Native graph, Cypher, APOC |
| LLM | Groq (Llama 3.3 70B) | Fast inference, good reasoning |
| ML | scikit-learn | Isolation Forest for anomalies |
| Embeddings | Not used | Cypher-grounded, no vector search |

---

## Key Technical Decisions

### 1. Connection as an Edge (and the Road Not Taken)

**Problem**: Where should per-flow metadata live — on the edge, or on a node?

**What we built**: connections are `CONNECTED_TO` **edges** between IP nodes,
carrying `protocol`, `port`, `bytes`, and a timestamp or anomaly flag:

```
IP_A ──CONNECTED_TO {protocol, port, bytes, timestamp}──▶ IP_B
```

Every node is stored under a single `:Node` label with its kind in a `type`
property (`InternalIP`, `ExternalIP`, `Port`, `AttackType`). Edge properties are
flattened onto the relationship, so you read `r.bytes`, not `r.properties.bytes`.

**The alternative we rejected** — promoting each connection to its own node:

```
IP_A ──SOURCE_OF──▶ Connection ──TARGET_OF──▶ IP_B
                        │
                        └── USED_PORT ──▶ 22
```

That model makes per-connection metadata and attack chaining natural, and it is
what a mature version of this system would want. The cost is one extra node per
flow: on the full UNSW-NB15 release that is millions of nodes for data already
addressable through edge properties. We kept connections as edges and accepted
the ceiling it imposes — see [Roadmap](#4-attack-chain-modeling-roadmap).

> **Not implemented.** `Connection` nodes, `SOURCE_OF` and `TARGET_OF` do not
> exist in the current schema. Cypher assuming them returns zero rows. Working
> queries are in [CYPHER_QUERIES.md](CYPHER_QUERIES.md#part-1--queries-that-run-today).

### 2. Template-Constrained Cypher (Anti-Hallucination)

**Problem**: Free-form LLM Cypher generation is dangerous.

**Solution**: Two-stage approach:
1. LLM classifies intent → returns `{intent: "anomalies", entities: {}}`
2. Intent maps to a pre-written Cypher template; user input arrives only as
   bound `$parameters`, never as concatenated text

```python
CYPHER_TEMPLATES = {
    QueryIntent.ANOMALIES: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\d+\\.\\d+\\.\\d+\\.\\d+'
        MATCH (ip)-[r:CONNECTED_TO|CONNECTS_TO]->()
        WITH ip.label AS ip_address,
             count(DISTINCT COALESCE(r.port, 0)) AS distinct_ports,
             count(r) AS connections
        WHERE distinct_ports > 5 OR connections > 30
        RETURN ip_address, distinct_ports AS ports_accessed, connections,
               CASE
                   WHEN distinct_ports > 10 AND connections > 50 THEN 'Critical'
                   WHEN distinct_ports > 5 THEN 'High'
                   ELSE 'Medium'
               END AS severity
        ORDER BY distinct_ports DESC, connections DESC
        LIMIT 15
    """
}
```

Note the template infers anomalies **behaviourally** from graph structure —
port fan-out and connection volume — rather than reading a precomputed
`is_anomaly` flag. Matching IP nodes by dotted-quad label also keeps `Port`
nodes out of the result without a separate exclusion clause.

**Result**: Zero hallucination, guaranteed valid Cypher.

### 3. Graph-Native Anomaly Detection

**Problem**: ML anomaly detection misses structural patterns.

**Solution**: Combine ML with graph algorithms:

| Method | What it Detects |
|--------|-----------------|
| Isolation Forest | Statistical outliers in features |
| Degree Spike | IPs with connection count > mean + 2σ |
| Fan-Out Detection | Single IP → many ports on same target |
| Protocol Rarity | Rare protocols (< 1% of traffic) |
| Suspicious Ports | Known malware ports (4444, 31337, etc.) |

Each anomaly includes **explainability**:
```json
{
  "anomaly_type": "degree_spike",
  "entity": "149.171.126.1",
  "baseline": 22.7,
  "observed": 254,
  "confidence_score": 0.785,
  "reason": "IP has 254 connections, significantly above average of 22.7"
}
```

### 4. Attack Chain Modeling (Roadmap)

**Problem**: Security analysts think in attack chains, not flat data.

**Intended solution**: explicit causal edges between attack stages, enabling
kill-chain traversal:

```
CredentialAccess ──LEADS_TO──▶ LateralMovement ──LEADS_TO──▶ Exfiltration
```

```cypher
MATCH path = (start)-[:LEADS_TO*1..5]->(end:Node {type: 'Exfiltration'})
RETURN [n IN nodes(path) | n.label] AS attack_chain
```

> **Not implemented.** No writer emits `LEADS_TO`, and no stage node types exist.
> The hard part is not the schema but inferring causal order between stages from
> timestamped flows — a temporal-correlation problem this project does not solve
> yet (see [ML Caveats](#ml-caveats): no temporal correlation between events).
>
> What *is* implemented: multi-stage attackers are identified behaviourally, by
> port fan-out combined with connection volume, via the
> `MULTI_STAGE_ATTACKERS` intent.

### 5. Entity Class Separation (Roadmap)

**Problem**: Mixing analyst inference with raw telemetry pollutes signal.

**Intended solution**: tag every entity with an `entity_class`:

| Class | Source | Example |
|-------|--------|---------|
| `telemetry` | Network logs | IPs, Ports, Connections |
| `semantic` | Text extraction | Devices, Organizations |
| `security` | Threat inference | Threats, Attack types |

> **Not implemented.** No writer sets `entity_class`. The distinction was
> meaningful when the text/URL extraction path was live; with only telemetry
> ingest wired up, `n.type` serves as the available proxy — `AttackType` nodes are
> inferred, IP and Port nodes are measured.

---

## Performance Characteristics

### Observed Scale

Indicative figures from local development runs against Neo4j 5 in Docker on a
laptop — not a benchmark. No formal performance testing has been done.

| Metric | Observed |
|--------|----------|
| CSV ingestion | ~5,000 rows in tens of seconds |
| Nodes per graph | 2,000+ |
| Startup auto-process cap | 2,000 rows per file |
| LLM response | 2-4s (Groq) |

Treat these as orders of magnitude. Ingestion time is dominated by per-row
parsing and the Neo4j write batch; query latency depends heavily on whether a
query is anchored on `(g:Graph {id: $graph_id})`.

### Indexes Used

Created at startup by `Neo4jService.ensure_indexes()`:

```cypher
CREATE INDEX IF NOT EXISTS FOR (g:Graph) ON (g.id);
CREATE INDEX IF NOT EXISTS FOR (n:Node) ON (n.label);
CREATE INDEX IF NOT EXISTS FOR (n:Node) ON (n.type);
```

Plus a uniqueness constraint on `n.id`, and a text index on `n.label` where the
Neo4j edition supports one. There is deliberately no index on `is_anomaly`: it is
a low-cardinality boolean that every query already pairs with a `type` predicate.

---

## Limitations (Honest Assessment)

### Detection Limitations

| Gap | Impact | Mitigation |
|-----|--------|------------|
| No encrypted traffic analysis | Can't inspect TLS content | Metadata-based detection |
| Batch processing only | Not real-time | Could add stream processing |
| Dataset bias | UNSW-NB15 patterns only | Train on production data |

### ML Caveats

- Isolation Forest finds statistical outliers, not confirmed attacks
- Thresholds (mean + 2σ) are heuristics, not optimized
- No temporal correlation between events

### RAG Limitations

- Cypher templates are finite (13 intents currently)
- Can't answer arbitrary analytical questions
- Depends on LLM intent classification accuracy

### Data Fidelity Caveats

Two of the three supported ingest formats synthesize fields the source data does
not carry, which bounds what the results can mean:

- **Preprocessed UNSW-NB15** ships without IP addresses, so the loader derives
  them from each row's `id`. Connection topology on that format reflects row
  ordering, not real host behaviour.
- **CICIDS2017** byte counts are generated randomly, even when the CSV has real
  IP columns — so volume-based conclusions (notably data exfiltration) do not
  hold on that format.

Attack labels and flow features remain genuine in both cases. Use the full
UNSW-NB15 release when topology and volume must be trustworthy. See
[../backend/sample_data/README.md](../backend/sample_data/README.md).

---

## API Reference

### Core Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/upload-csv` | POST | Ingest network data (CSV, format auto-detected) |
| `/api/network/ingest` | POST | Ingest structured JSON logs |
| `/api/network/query` | POST | Grounded RAG query over the network graph |
| `/api/query` | POST | Generic natural language query |
| `/api/network/analyze/{graph_id}` | GET | Full security analysis |

The full list of 21 endpoints is in [../README.md](../README.md#api-reference).

### Query Example

**Request:**
```json
POST /api/query
{
  "query": "What anomalies were detected?",
  "graph_id": "network_security"
}
```

**Response:**
```json
{
  "answer": "Found 12 anomalies with highest score 1.0 for 175.45.176.0...",
  "intent": "anomalies",
  "cypher_template_used": "MATCH (g:Graph...)...",
  "grounding_context": "Query results: 12 rows...",
  "query_results_count": 12
}
```

---

## Future Improvements

Carried over from the roadmap sections above:

1. **Attack chain modeling**: `LEADS_TO` edges between stage nodes, which first
   requires temporal correlation between flows (§4)
2. **Connection-as-node**: promote flows to first-class entities where per-flow
   metadata justifies the node-count cost (§1)
3. **Entity class tagging**: `entity_class` on every node, meaningful again once a
   second ingest modality is live (§5)

Beyond that:

4. **Real-time streaming**: Kafka integration for live detection
5. **MITRE ATT&CK mapping**: Auto-tag detected techniques
6. **Alert enrichment**: Pull context from VirusTotal, AbuseIPDB
7. **Graph visualization**: Frontend for attack path exploration
8. **Multi-tenant**: Organization-level graph isolation

---

## Conclusion

This project demonstrates:
- ✅ Graph-based security modeling with a deliberate, documented schema
- ✅ Hybrid anomaly detection (ML + graph-native) with explainability records
- ✅ Grounded RAG that cannot emit a hallucinated query
- ✅ Confidence gating that declines to answer rather than guessing
- ✅ Honest documentation of limitations and of what is not built

The key insight: **Security data is inherently relational**. Modeling it as a graph enables queries that flat logs cannot answer.

---

## Repository

- **Documentation**: [CYPHER_QUERIES.md](CYPHER_QUERIES.md),
  [TECHNICAL_REFERENCE.md](TECHNICAL_REFERENCE.md),
  [../CODEBASE.md](../CODEBASE.md)
- **Run locally**: `docker compose up -d`

---

*Developed as a demonstration of production-grade security engineering principles.*
