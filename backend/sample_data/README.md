# Sample data

Drop network traffic CSVs in this directory. On startup the API scans it and
ingests any file it has not seen before (disable with `ENABLE_AUTO_PROCESS=false`).

Datasets are **not committed** — `.gitignore` excludes `*.csv`, `*.json` and the
`.processed_files` marker, so this directory arrives empty apart from
`dataset_converter.py` and this README. Download a dataset yourself, or generate
synthetic traffic with the converter below.

## How auto-processing works

- Only files ending in `.csv` are picked up. **JSON is ignored** by the scanner —
  see [Using the converter](#using-the-converter) for how to load JSON.
- Each ingested filename is appended to `.processed_files` so restarts do not
  re-ingest the same data. To force a re-ingest, delete that file (or the single
  line naming your CSV).
- Files are capped at 2000 rows on the startup path. The `/api/network/upload-csv`
  endpoint defaults to 5000 and takes a `max_rows` parameter.
- Format is auto-detected from the header row; you do not pass a format flag.

## Supported formats and data fidelity

This matters for interpreting results. The three formats do **not** carry equal
information, and two of them synthesize fields the source data lacks.

| Format | Detected by | Source IPs | Byte counts |
|---|---|---|---|
| **UNSW-NB15** (full, ~49 columns) | headerless rows whose first value is an IP, or a `srcip` column | real (`srcip`/`dstip`) | real (`sbytes`/`dbytes`) |
| **UNSW-NB15 preprocessed** (training/testing splits) | `id` + `attack_cat` + `label`, but no `srcip` | **synthetic** — derived deterministically from the row `id` | real (`sbytes`/`dbytes`) |
| **CICIDS2017** | headers containing `Destination Port` / `Label` | real when `Source IP`/`Destination IP` are present, otherwise **synthetic** | **always synthetic** (random 100–5000) |

### What "synthetic" means for your results

- **Preprocessed UNSW-NB15** publishes flow features with the addresses stripped.
  To build a graph at all, the loader manufactures IPs from each row's `id`
  (`192.168.x.x` / `10.x.x.x`). They are stable and repeatable, but they are
  **not real hosts** — an "attacker" IP in the graph is an artifact of row
  ordering. Attack labels and flow features remain genuine, so anomaly scoring
  and attack-type analysis are meaningful; *who talked to whom* is not.

- **CICIDS2017** byte counts are generated unconditionally, even when the CSV has
  real IP columns. Anything keyed on volume — most importantly
  `/api/network/detect-exfiltration` — is therefore measuring random numbers on
  this format. Attack labels and destination ports are real; treat the transfer
  sizes as filler.

Use the full UNSW-NB15 release, or your own logs, when topology and volume need
to be trustworthy.

## Using the converter

`dataset_converter.py` turns raw research datasets into the JSON shape the
ingest API accepts, and can synthesize traffic when you have no dataset at hand:

```bash
cd backend/sample_data

# Synthetic traffic: 200 entries by default -> realistic_traffic.json
python dataset_converter.py generate
python dataset_converter.py generate custom.json 500

# Convert a real dataset (max_rows is optional)
python dataset_converter.py cicids cicids2017_cleaned.csv converted.json 1000
python dataset_converter.py unsw  UNSW-NB15_1.csv unsw_converted.json 2000
python dataset_converter.py nsl   KDDTrain+.txt  nsl_converted.json 1000
```

The converter writes **JSON**, which the startup scanner skips. Load it through
the API instead:

```bash
curl -X POST http://localhost:8000/api/network/ingest \
  -H "Content-Type: application/json" \
  -d @realistic_traffic.json
```

To use the auto-processing path instead, put an unconverted `.csv` in this
directory and restart the API — the loader detects the format itself.

## Where to get the datasets

- **UNSW-NB15** — https://research.unsw.edu.au/projects/unsw-nb15-dataset
  (prefer the full CSVs over the preprocessed splits; see the table above)
- **CICIDS2017** — https://www.unb.ca/cic/datasets/ids-2017.html
- **NSL-KDD** — https://www.unb.ca/cic/datasets/nsl.html
