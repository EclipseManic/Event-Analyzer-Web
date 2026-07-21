<p align="center">
  <img src="https://img.shields.io/badge/Flask-3.1-%23000?logo=flask" alt="Flask">
  <img src="https://img.shields.io/badge/Python-3.13-%233776AB?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Vue-3-%234FC08D?logo=vuedotjs" alt="Vue">
  <img src="https://img.shields.io/badge/SQLite-%23003B57?logo=sqlite" alt="SQLite">
  <img src="https://img.shields.io/badge/pytest-59%20passing-%230A9EDC?logo=pytest" alt="Tests">
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="License">
</p>

<h1 align="center">🕵️ Event-Analyzer</h1>
<p align="center"><b>A fast, analyst-first Windows EVTX viewer with built-in IOC extraction, Sigma rule matching, and MITRE ATT&CK mapping.</b></p>
<p align="center">
  <i>Upload, filter, search, bookmark, annotate, and export — all in a responsive single-page interface.</i>
</p>

<hr>

## ✨ Features at a Glance

<table>
<tr>
<td width="50%">

<h3>📂 Core Viewer</h3>

- Upload one or many <code>.evtx</code> files simultaneously
- Filter by event ID, channel, provider, process, user, hostname
- Sort by timestamp (ascending / descending)
- Export filtered results to <b>CSV</b> or <b>JSON</b>
- Paginated browsing with configurable page size
- Timeline view aggregated by minute

</td>
<td width="50%">

<h3>🛡️ Security Analysis</h3>

- **IOC Extraction** — IPs, domains, URLs, hashes (MD5/SHA1/SHA256/SHA512), file paths, registry keys, process names
- **Sigma Rule Matching** — Community rules compiled on-the-fly, level-based filtering, result caching
- **MITRE ATT&CK Mapping** — Event categories mapped to technique IDs with reverse lookup

</td>
</tr>
<tr>
<td>

<h3>📊 Reports & Notes</h3>

- One-click HTML investigation report with summary cards, sigma alert tables, IOC breakdowns, channel listings
- Rich-text notes per investigation
- Bookmark important events for quick reference

</td>
<td>

<h3>⚡ Performance</h3>

- Rust-based EVTX parser (<code>pyevtx-rs</code>) — fast
- ThreadPoolExecutor for parallel per-event analysis
- Bulk batch inserts (2k events / 500 IOCs per commit)
- Sigma match result cache (LRU, 50k entries)
- Quick-rejection via per-field mega-regexes

</td>
</tr>
</table>

<p align="center">
  <b>Multiple concurrent investigations</b> · Real-time progress tracking · Mid-ingestion cancellation
</p>

<hr>

## 🚀 Quick Start

```powershell
# 1) Install dependencies
pip install -r requirements.txt

# 2) Optional: customize settings
copy settings\.env.example settings\.env

# 3) Launch the server
python run.py
```

<p align="center">
  Open <b><a href="http://127.0.0.1:5050">http://127.0.0.1:5050</a></b> in your browser.
</p>

<hr>

## ⚙️ Configuration

All settings are controlled via environment variables (or <code>settings/.env</code>).

| Variable | Default | Description |
|---|---|---|
| `EVTX_VIEWER_HOST` | `127.0.0.1` | Bind address |
| `EVTX_VIEWER_PORT` | `5050` | Port |
| `EVTX_VIEWER_DEBUG` | `false` | Flask debug mode |
| `EVTX_VIEWER_AUTO_LAUNCH` | `true` | Open browser on startup |
| `EVTX_VIEWER_MAX_UPLOAD_MB` | `100` | Per-file upload limit |
| `EVTX_VIEWER_MAX_FILES` | `500` | Maximum files per upload request |
| `EVTX_VIEWER_MAX_REQUEST_MB` | `2048` | Maximum total request size |
| `EVTX_VIEWER_PAGE_LIMIT` | `200` | Default pagination limit |
| `EVTX_VIEWER_MAX_EVENTS_PER_FILE` | `0` | Max events per EVTX file (`0` = unlimited) |
| `EVTX_VIEWER_STORE_RAW` | `false` | Store raw JSON in database |
| `EVTX_VIEWER_CONCURRENT_INGEST` | `2` | Max parallel ingestion threads |
| `EVTX_VIEWER_DELETE_AFTER_INGEST` | `true` | Delete source EVTX after successful ingest |
| `EVTX_VIEWER_DATA_DIR` | `data/evtx_viewer` | Data root directory |

<hr>

## 🏗️ Architecture

```
┌──────────────┐      ┌───────────────────┐      ┌──────────────┐      ┌──────────────────┐
│   Browser    │ ───> │   Flask API       │ ───> │  Ingestion   │ ───> │  SQLite DB       │
│  (Vue 3 SPA) │ <─── │   (app/api.py)     │ <─── │  Pipeline    │ <─── │  (app/db.py)      │
└──────────────┘      └───────────────────┘      └──────┬───────┘      └──────────────────┘
                                                         │
                                              ┌──────────┼──────────┐
                                              ▼          ▼          ▼
                                       ┌──────────┐ ┌────────┐ ┌───────────┐
                                       │  EVTX    │ │  IOC   │ │  Sigma    │
                                       │  Parser  │ │ Extract│ │  Match    │
                                       │(.py, Rust)│ │(.py)   │ │(.py)      │
                                       └──────────┘ └────────┘ └───────────┘
                                                         │          │
                                                         ▼          ▼
                                                  ┌──────────┐ ┌───────────┐
                                                  │  MITRE   │ │  Config   │
                                                  │  Mapper  │ │  & Logger │
                                                  │(.py)     │ │(.py)      │
                                                  └──────────┘ └───────────┘
```

### Data Flow

1. **Upload** — EVTX files are uploaded via the web interface and saved to the uploads directory
2. **Parse** — Each file is parsed by the Rust-based `pyevtx-rs` backend, yielding structured event dictionaries
3. **Analyze** — Every event goes through three analysis steps in parallel:
   - **IOC Extraction** — Regex-based scanning on `command_line`, `description`, `process_name`, and structured fields (`source_ip`, `hash_value`, etc.)
   - **Sigma Matching** — Compiled rule conditions matched against event fields with quick-rejection via mega-regexes and LRU result caching
   - **MITRE Mapping** — Event category → MITRE ATT&CK technique ID lookup
4. **Store** — Events, IOCs, and sigma matches are bulk-inserted into SQLite, and the full-text search index is rebuilt
5. **Serve** — The Flask API serves data to the Vue 3 frontend for filtering, sorting, bookmarking, note-taking, and report generation

<hr>

## 🌐 REST API

### Investigations

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations` | List all investigations |
| `GET` | `/api/investigations/{id}` | Get investigation details |
| `DELETE` | `/api/investigations/{id}` | Delete investigation (async) |
| `GET` | `/api/investigations/{id}/progress` | Ingestion progress |

### Events

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations/{id}/events` | List events (paginated, filterable) |
| `GET` | `/api/investigations/{id}/events/count` | Event count with filters |
| `GET` | `/api/investigations/{id}/events/{event_id}` | Single event detail |
| `GET` | `/api/investigations/{id}/events/export` | Export events (CSV or JSON) |
| `GET` | `/api/investigations/{id}/channels` | List event channels |
| `GET` | `/api/investigations/{id}/providers` | List event providers |
| `GET` | `/api/investigations/{id}/source-files` | List source EVTX files |
| `GET` | `/api/investigations/{id}/timeline` | Timeline aggregation |

### Security Analysis

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations/{id}/iocs` | List IOCs (paginated, filterable by type) |
| `GET` | `/api/investigations/{id}/iocs/summary` | IOC summary by type |
| `GET` | `/api/investigations/{id}/iocs/export` | Export IOCs (CSV or JSON) |
| `GET` | `/api/investigations/{id}/sigma` | List sigma matches grouped by rule |
| `GET` | `/api/investigations/{id}/sigma/events` | Events matching a specific sigma rule |
| `GET` | `/api/investigations/{id}/sigma/summary` | Sigma match summary |
| `GET` | `/api/investigations/{id}/sigma/export` | Export sigma matches (CSV or JSON) |

### Notes, Bookmarks & Reports

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations/{id}/notes` | Get investigation notes |
| `PUT` | `/api/investigations/{id}/notes` | Save investigation notes |
| `POST` | `/api/investigations/{id}/bookmarks` | Add event bookmark |
| `DELETE` | `/api/investigations/{id}/bookmarks/{event_id}` | Remove event bookmark |
| `GET` | `/api/investigations/{id}/bookmarks` | List bookmarked event IDs |
| `GET` | `/api/investigations/{id}/report` | Download HTML report |

### Ingestion

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload EVTX files (multipart) |

### CLI Commands

```powershell
flask update-sigma    # Fetch latest Sigma rules from community repositories
flask backfill        # Re-extract IOCs & Sigma matches for existing investigations
```

<hr>

## 🧪 Testing

The project includes **59 tests** covering every module.

```powershell
# Run all tests
pytest test/test_app.py -v

# Run with coverage
pytest test/test_app.py --cov=app -v
```

| Module | Tests | What's Covered |
|---|---|---|
| `config` | 3 | Defaults, caching, env overrides |
| `db` | 15 | CRUD, bulk inserts, bookmarks, notes, sigma |
| `evtx_parser` | 5 | JSON event parsing, field extraction, dedup |
| `ioc_extractor` | 9 | IP, hash, file, registry, domain, URL, dedup |
| `sigma_matcher` | 5 | Loading, matching (hit & miss), caching, field mapping |
| `mitre_mapper` | 4 | Category mapping, fallback, reverse lookup |
| `ingest` | 3 | Pipeline, stop event, source cleanup |
| `api` | 11 | Health, CRUD, upload, bookmarks, notes, export |
| `report_generator` | 2 | Valid & invalid investigation HTML output |
| `backfill` | 2 | Backfill with and without events |
| `sigma_updater` | 3 | YAML parsing, detection conversion, rule filtering |

<hr>

## 🗂️ Project Structure

```
Event-Analyzer/
├── app/
│   ├── __init__.py
│   ├── api.py              # Flask routes & app factory
│   ├── backfill.py         # One-time IOC/Sigma backfill
│   ├── config.py           # Environment-based configuration
│   ├── db.py               # SQLite database layer
│   ├── evtx_parser.py      # Rust-based EVTX parser
│   ├── ingest.py           # Ingestion pipeline orchestrator
│   ├── ioc_extractor.py    # IOC extraction (regex)
│   ├── logger.py           # Logging helpers
│   ├── mitre_mapper.py     # MITRE ATT&CK mapping
│   ├── report_generator.py # HTML report generator
│   ├── sigma_matcher.py    # Sigma rule matching engine
│   ├── sigma_updater.py    # Community rule downloader (output goes to data/sigma/)
│   ├── utils.py            # Shared helpers
│   ├── static/
│   │   ├── app.js          # Vue 3 frontend
│   │   └── styles.css
│   └── templates/
│       └── index.html
├── settings/
│   └── .env.example        # Environment template
├── data/
│   ├── evtx_viewer/        # SQLite DB & uploads
│   └── sigma/              # Compiled Sigma rules, logsource map, field list
├── test/
│   └── test_app.py         # Comprehensive test suite
├── requirements.txt
├── run.py                  # Entry point
└── README.md
```

<hr>

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `flask` 3.x | Web framework |
| `evtx` (pyevtx-rs) | Rust-based EVTX parser |
| `python-dotenv` | `.env` file loading |
| `PyYAML` | Sigma YAML rule parsing |
| `pytest` | Test runner |

<hr>

<p align="center">
  <sub>Built with ❤️ for incident responders and forensic analysts.</sub>
</p>
