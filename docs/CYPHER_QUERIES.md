# Cypher Query Guide

Hand-written Cypher for exploring the security graph directly — in Neo4j Browser,
`cypher-shell`, or your own tooling. These are *not* the queries the RAG layer
runs; those live in `CYPHER_TEMPLATES` in
[`backend/app/services/cypher_query_service.py`](../backend/app/services/cypher_query_service.py)
and are documented in [TECHNICAL_REFERENCE.md](TECHNICAL_REFERENCE.md).

The document is split in two:

- **[Part 1 — Queries that run today](#part-1--queries-that-run-today)** are
  verified against the schema this codebase actually writes. Copy, paste, run.
- **[Part 2 — Aspirational patterns](#part-2--aspirational-patterns)** target a
  richer schema the storage layer does not build yet. They are kept as design
  sketches for the roadmap and **will return zero rows** as written.

---

## The schema you are querying

Read this first — most Cypher written against this graph fails for one of two
reasons, and both are schema misunderstandings.

**1. There is one node label.** Every node is stored under `:Node`. The kind of
thing it is lives in a `type` **property**, not a label:

| `type` value | Created from | Properties |
|---|---|---|
| `InternalIP` | RFC1918 source/dest addresses | `is_internal`; plus `is_anomaly`, `anomaly_score`, `anomaly_types` on the CSV path |
| `ExternalIP` | all other addresses | same as above |
| `Port` | each distinct destination port | `port_number`, `service`, `is_suspicious` |
| `AttackType` | `attack_cat` labels (CSV ingest only) | `name`, `is_threat` |

So you write `MATCH (n:Node) WHERE n.type = 'Port'`, never `MATCH (n:Port)`.

**2. Properties are flat.** The writer does `SET n += node.properties`
([`neo4j_service.py:164`](../backend/app/services/neo4j_service.py#L164)), which
spreads the map onto the node. Read `n.confidence`, **not** `n.properties.confidence`.

Relationships:

| Type | From → To | Properties |
|---|---|---|
| `CONTAINS` | `:Graph` → `:Node` | — |
| `CONNECTED_TO` | IP → IP | `protocol`, `port`, `bytes`, and `timestamp` (JSON ingest) or `is_anomaly` (CSV ingest) |
| `USES_PORT` | IP → Port | none |

> **`bytes` is sent + received combined.** There is no `bytes_sent` property on
> an edge. Reading one returns null, and `COALESCE(r.bytes_sent, 0)` silently
> yields a permanent zero — a bug this project shipped and has since fixed.

Node-level anomaly scores (`is_anomaly`, `anomaly_score`, `anomaly_types`) are
written by the **CSV/auto-processing path only**
([`auto_processor.py:728`](../backend/app/services/auto_processor.py#L728)).
Graphs built through `POST /api/network/ingest` carry anomaly data on the
*edges* instead, so queries in Part 1 that read node-level scores return nothing
for JSON-ingested graphs.

---

# Part 1 — Queries that run today

## 1. Attack surface: which external IPs touch the most internal hosts

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ext:Node)
WHERE ext.type = 'ExternalIP'
OPTIONAL MATCH (internal:Node)-[:CONNECTED_TO]->(ext)
WHERE internal.type = 'InternalIP'
WITH ext,
     collect(DISTINCT internal.label) AS connected_hosts,
     count(DISTINCT internal) AS host_count
WHERE host_count > 1
RETURN ext.label AS external_ip,
       host_count AS internal_hosts_connected,
       connected_hosts[0..5] AS sample_hosts,
       CASE WHEN ext.is_anomaly THEN 'suspicious' ELSE 'normal' END AS risk_status
ORDER BY host_count DESC
LIMIT 20
```

One external address pulling connections from many internal hosts is the shape
of C2 beaconing or a shared exfil endpoint. Note `count(DISTINCT internal)` —
plain `count(internal)` counts connection rows, not hosts, and inflates the
number for any host that connected twice.

## 2. Threat hunting on scored IPs

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(src:Node)-[r:CONNECTED_TO]->(dst:Node)
WHERE src.is_anomaly = true
  AND src.anomaly_score > 0.7
  AND dst.type = 'ExternalIP'
RETURN src.label AS suspicious_ip,
       src.anomaly_score AS score,
       src.anomaly_types AS threat_indicators,
       collect(DISTINCT dst.label) AS external_destinations,
       count(r) AS connection_count
ORDER BY score DESC
LIMIT 20
```

CSV-ingested graphs only — see the note above about where anomaly scores land.

## 3. Port scan detection

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(src:Node)-[r:CONNECTED_TO]->(dst:Node)
WITH src, dst, collect(DISTINCT r.port) AS ports
WHERE size(ports) >= 10
RETURN src.label AS scanner_ip,
       dst.label AS target_ip,
       size(ports) AS ports_scanned,
       ports[0..10] AS sample_ports,
       CASE
         WHEN size(ports) > 50 THEN 'high'
         WHEN size(ports) > 20 THEN 'medium'
         ELSE 'low'
       END AS confidence
ORDER BY ports_scanned DESC
```

The `PORT_SCANNERS` RAG intent uses a threshold of `> 5` rather than `>= 10`;
this standalone version is deliberately stricter for manual hunting.

## 4. Degree spike detection

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
WHERE n.type IN ['InternalIP', 'ExternalIP']
WITH n, count { (n)-[:CONNECTED_TO]->() } AS out_degree
WITH collect({node: n, degree: out_degree}) AS data
WITH data,
     reduce(s = 0.0, x IN data | s + x.degree) / size(data) AS mean
WITH data, mean,
     sqrt(reduce(s = 0.0, x IN data | s + (x.degree - mean)^2) / size(data)) AS std_dev
UNWIND data AS item
WITH item.node AS n, item.degree AS degree, mean, std_dev
WHERE std_dev > 0 AND degree > mean + (2 * std_dev)
RETURN n.label AS high_activity_ip,
       degree AS connections,
       round(mean, 2) AS graph_average,
       round((degree - mean) / std_dev, 2) AS z_score,
       'degree_spike' AS anomaly_type
ORDER BY degree DESC
LIMIT 15
```

Three details matter here. `count { ... }` replaces the deprecated
`size((n)-[...]->())` pattern-comprehension form, removed in Neo4j 5. The mean
seeds with `0.0` — seeding with integer `0` gives integer division and a wrong
baseline. And `std_dev > 0` guards the uniform-degree case, where every node
would otherwise clear a threshold of `mean + 0`.

`GraphAnomalyDetector` applies the same rule in Python with an extra absolute
floor (`degree > 5`) so tiny graphs don't report noise.

## 5. Traffic volume by talker

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
WHERE ip.type IN ['InternalIP', 'ExternalIP']
OPTIONAL MATCH (ip)-[r:CONNECTED_TO]->()
WITH ip, count(r) AS connections, sum(COALESCE(r.bytes, 0)) AS total_bytes
RETURN ip.label AS ip_address,
       connections,
       total_bytes
ORDER BY total_bytes DESC
LIMIT 10
```

`total_bytes`, not `bytes_sent` — the stored value combines both directions.

## 6. Suspicious port exposure

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(p:Node)
WHERE p.type = 'Port' AND p.is_suspicious = true
OPTIONAL MATCH (ip:Node)-[:USES_PORT]->(p)
RETURN p.label AS port,
       p.port_number AS port_number,
       p.service AS service,
       count(DISTINCT ip) AS hosts_involved,
       collect(DISTINCT ip.label)[0..10] AS sample_hosts
ORDER BY hosts_involved DESC
```

`is_suspicious` comes from the curated list in `network_parser.is_suspicious_port`
— `[4444, 5555, 6666, 7777, 31337, 12345, 54321, 1234]` — not from a range check.

## 7. Attack types and their sources

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(a:Node)
WHERE a.type = 'AttackType'
OPTIONAL MATCH (ip:Node)-[r]->(a)
RETURN a.label AS attack_type,
       count(DISTINCT ip) AS source_ips,
       collect(DISTINCT ip.label)[0..10] AS sample_sources
ORDER BY source_ips DESC
```

`AttackType` nodes exist only for CSV formats carrying an `attack_cat` column
(UNSW-NB15) or a `Label` column (CICIDS2017).

## 8. Graph inventory

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
RETURN n.type AS node_type, count(*) AS count
ORDER BY count DESC
```

The fastest sanity check after an ingest. If `AttackType` is missing, the source
CSV had no label column; if `Port` counts look impossibly high, you are probably
looking at ephemeral client ports.

---

# Part 2 — Aspirational patterns

**These queries do not run against the current schema.** They are design
sketches for a richer model — kept because they describe where the graph is
headed, not what it holds. Each notes what would have to exist first.

The gap in one line: the current model stores a **connection as an edge**, while
these queries assume a **connection as a node** with causal `LEADS_TO` chaining
between attack stages.

## A. Attack chain traversal

*Requires:* `LEADS_TO` relationships and stage nodes (`Exfiltration`,
`CredentialAccess`, `LateralMovement`). Nothing writes these today.

```cypher
MATCH path = (start:Node)-[:LEADS_TO*1..5]->(end:Node)
WHERE end.type = 'Exfiltration'
RETURN [n IN nodes(path) | n.label] AS attack_chain,
       [n IN nodes(path) | n.type] AS stages,
       length(path) AS chain_length,
       end.confidence AS confidence
ORDER BY chain_length DESC
LIMIT 10
```

Building this means promoting connections to nodes and inferring causal order
between stages — a temporal-correlation problem, not just a schema change.

## B. Lateral movement from compromised credentials

*Requires:* `CredentialAccess` / `LateralMovement` node types, `LEADS_TO` and
`TARGET_OF` relationships, and `type: 'Connection'` nodes.

```cypher
MATCH (cred:Node {type: 'CredentialAccess'})-[:LEADS_TO]->(lateral:Node {type: 'LateralMovement'})
OPTIONAL MATCH (lateral)-[:INDICATES|LEADS_TO]->(conn:Node {type: 'Connection'})
OPTIONAL MATCH (conn)-[:TARGET_OF]->(target:Node)
RETURN cred.label AS initial_compromise,
       lateral.label AS movement_type,
       conn.protocol AS protocol,
       conn.port AS port,
       collect(DISTINCT target.label) AS compromised_systems,
       lateral.confidence AS confidence
```

## C. Connection-centric analysis

*Requires:* connections as first-class nodes with `SOURCE_OF` / `TARGET_OF` edges.

```cypher
MATCH (conn:Node {type: 'Connection'})
WHERE conn.port IN [4444, 5555, 31337, 12345]
   OR conn.protocol = 'IRC'
OPTIONAL MATCH (src)-[:SOURCE_OF]->(conn)
OPTIONAL MATCH (conn)-[:TARGET_OF]->(dst)
RETURN conn.label AS connection,
       conn.timestamp AS timestamp,
       conn.port AS port,
       conn.protocol AS protocol,
       src.label AS source,
       dst.label AS destination,
       'malware_port' AS threat_type
```

The trade-off is real: connection-as-node makes per-connection metadata and
attack chaining natural, at the cost of roughly one extra node per flow. On
UNSW-NB15 at full scale that is millions of nodes, which is why the current
model keeps connections as edges.

Today, the equivalent question is answered against edges:

```cypher
MATCH (src:Node)-[r:CONNECTED_TO]->(dst:Node)
WHERE r.port IN [4444, 5555, 31337, 12345]
RETURN src.label AS source, dst.label AS destination,
       r.port AS port, r.protocol AS protocol, r.bytes AS total_bytes
```

## D. Entity class filtering

*Requires:* an `entity_class` property (`telemetry` / `semantic` / `security`)
on every node. The concept survives in the case study; the writer never sets it.

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
WHERE n.entity_class = 'security'
RETURN n.label AS finding, n.type AS category,
       n.confidence AS confidence, n.severity AS severity
ORDER BY n.confidence DESC
```

Until then, `n.type` is the available proxy: `AttackType` nodes are inferred,
IP and Port nodes are telemetry.

## E. Cross-graph correlation

*Requires:* a `graph_type` property on `:Graph` nodes. Graph nodes currently
carry only `id`, `created`, and `updated`.

```cypher
MATCH (g1:Graph)-[:CONTAINS]->(n1:Node)
WHERE g1.graph_type = 'semantic'
MATCH (g2:Graph)-[:CONTAINS]->(n2:Node)
WHERE g2.graph_type = 'telemetry' AND n2.label = n1.label
RETURN n1.label AS common_entity, n1.type AS entity_type,
       g1.id AS semantic_graph, g2.id AS telemetry_graph
```

Cross-source correlation *is* implemented — in Python, by
`GraphMerger.find_correlations()`, exposed at
`GET /api/network/correlations/{graph_id}`. This query is the Cypher-native
version that a `graph_type` property would unlock.

## F. Timeline reconstruction

*Requires:* timestamps on nodes. Timestamps live on `CONNECTED_TO` edges, and
only for the JSON ingest path.

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(e:Node)
WHERE e.timestamp IS NOT NULL
RETURN e.label AS event, e.type AS event_type, e.timestamp AS timestamp
ORDER BY e.timestamp
```

The edge-based version works today on JSON-ingested graphs:

```cypher
MATCH (src:Node)-[r:CONNECTED_TO]->(dst:Node)
WHERE r.timestamp IS NOT NULL
RETURN r.timestamp AS timestamp, src.label AS source,
       dst.label AS destination, r.port AS port
ORDER BY r.timestamp
LIMIT 100
```

---

## Performance notes

Three indexes are created at startup by `Neo4jService.ensure_indexes()`:

```cypher
CREATE INDEX IF NOT EXISTS FOR (g:Graph) ON (g.id);
CREATE INDEX IF NOT EXISTS FOR (n:Node) ON (n.label);
CREATE INDEX IF NOT EXISTS FOR (n:Node) ON (n.type);
```

plus a uniqueness constraint on `n.id` and, where the edition supports it, a
text index on `n.label` for `CONTAINS` searches.

Anchor every query on `(g:Graph {id: $graph_id})-[:CONTAINS]->` where you can.
Without it you scan every node across every stored graph, and this database is
designed to hold several at once.

---

## Quick reference

| Pattern | Use |
|---|---|
| `MATCH (n:Node) WHERE n.type = 'Port'` | Select a node kind (never `(n:Port)`) |
| `n.is_suspicious` | Flat property access (never `n.properties.x`) |
| `count { (n)-[:CONNECTED_TO]->() }` | Degree in Neo4j 5 |
| `sum(COALESCE(r.bytes, 0))` | Traffic volume, both directions |
| `count(DISTINCT x)` | Count entities, not matched rows |
| `collect(DISTINCT x)[0..5]` | Bounded sample in aggregates |
