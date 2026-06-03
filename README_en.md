git clone <your-repo-url>
# LORE · Reflective Offensive Knowledge Distillation Engine

[English](README_en.md) | [中文](README.md)

<div align="center">

### Reflective Offensive Knowledge Distillation Engine
LORE extracts reusable offensive and defensive knowledge from real penetration testing sessions and builds an evolving, searchable, and reflow-capable security knowledge base.

Badges

- Python 3.10+
- Flask dashboard
- RAGFlow integration

---

## Table of Contents

- Project Overview
- Core Capabilities
- System Architecture
- Knowledge Layer Model
- Quick Start
- Run Modes
- RAGFlow Routing (Important)
- Data Collection & Augmentation
- Project Status
- Dashboard Overview
- Project Structure
- Documentation Index
- FAQ
- Development & Testing
- Security & Compliance
- License

---

## Project Overview

LORE (Reflective Penetration Testing) is a layered knowledge distillation system for penetration testing scenarios. It transforms raw offensive/defensive logs into five categories of structured experience and uses cross-session fusion and gap-aware crawling to let the knowledge base evolve continuously.

One-line summary:

- Input: real penetration session logs + multi-source security corpora
- Process: Layer 0~4 pipeline distillation + XPEC fusion + gap-driven crawling
- Output: retrievable, explainable artifacts served via RAGFlow

![](./docs/images/fig1-macro-architecture.png)

---

## Core Capabilities

| Capability | Description |
|---|---|
| Layered pipeline (Layer 0~4) | Structured processing from raw logs to fused knowledge |
| Five artifact types | FACTUAL / PROCEDURAL_POS / PROCEDURAL_NEG / METACOGNITIVE / CONCEPTUAL |
| XPEC cross-session fusion | Multi-stage fusion to reduce noise and consolidate evidence |
| Gap-aware augmentation | Detects missing knowledge and triggers targeted crawling |
| RAGFlow reflow | Upload high-value artifacts to RAGFlow for retrieval |
| Dashboard | Visualize artifacts, sessions, and gap analysis |

---

## System Architecture

Entry points:

- Main pipeline: `run/run_full_pipeline.py`
- Interactive: `lore.py`
- Dashboard: `dashboard/app.py`

![](./docs/images/fig4-lore-architecture.png)

---

## Knowledge Layer Model

| Layer | Enum | Example |
|---|---|---|
| FACTUAL | FACTUAL | CVE details, affected versions |
| PROCEDURAL_POS | PROCEDURAL_POS | Successful command sequences, verification signals |
| PROCEDURAL_NEG | PROCEDURAL_NEG | Failed commands, error reasons, mitigation notes |
| METACOGNITIVE | METACOGNITIVE | Decision rules, strategy heuristics |
| CONCEPTUAL | CONCEPTUAL | Attack principles, tool mechanisms |

---

## Quick Start

1) Environment

```bash
git clone <your-repo-url>
cd LORE
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2) Config

- Required: `configs/config.yaml` (LLM and RAGFlow credentials, dataset IDs)
- Design-level settings: `configs/design.yaml`

3) Start Dashboard

```bash
cd dashboard
python app.py
```

Visit: http://localhost:5000

4) Run full pipeline

```bash
cd ..
python run/run_full_pipeline.py
```

---

## Run Modes

Interactive (recommended):

```bash
python lore.py
```

Command-line stages:

```bash
python run/run_layer0.py --log-dir logs --output-dir data/layer0_output
python run/run_layer1_llm_batch.py
python run/run_layer2_analysis.py --no-ragflow
python run/run_layer3_phase12.py
python run/run_layer3_phase34.py
python run/run_layer3_phase5.py
python run/run_layer4_gap_dispatch.py --no-crawl
python -m src.ragflow.uploader --source fused
```

Pipeline status:

```bash
python run/run_full_pipeline.py --status
```

---

## RAGFlow Routing (Important)

Default routing conventions:

| Knowledge Layer | Route Key |
|---|---|
| FACTUAL | dataset_factual |
| PROCEDURAL_POS | dataset_procedural_pos |
| PROCEDURAL_NEG | dataset_procedural_neg |
| METACOGNITIVE | dataset_metacognitive |
| CONCEPTUAL | dataset_metacognitive |
| Full archive | full_dataset |

Notes:

- METACOGNITIVE and CONCEPTUAL are combined into `dataset_metacognitive` by default.
- `full_dataset` is reserved for full archives and not used in normal uploads.

Example: upload only specific consolidated conceptual artifacts

```bash
python -m src.ragflow.uploader --source fused --exp-ids exp_consolidated_xxx,exp_consolidated_yyy --retry-502-max 8 --retry-base-sec 2.0
```

---

## Data Collection & Augmentation

Dual-track data collection: real-time crawlers and external knowledge base sync.

### Multi-source Crawlers

5 security data sources (CSDN / GitHub / Qi-AnXin / XianZhi / WeChat Official Accounts):

```bash
python crawlers/main_crawler.py --all -q "CVE-2024-xxxx" --yes
python crawlers/main_crawler.py --sources csdn,github -q "WebLogic deserialization" --max-pages 8
```

### WeChat Official Accounts

Seed account management, Sogou direct collection & native WeChat dual-mode, mitmdump proxy integration, article preview.

![](./docs/images/fig3-wechat-collection.png)

### External Knowledge Base Sync

One-click sync of 11 external security databases:

```bash
python crawlers/sync_data_light.py
python crawlers/sync_data_light.py --repos cisa-kev,cwe,nvd
```

| Database | Description |
|---|---|
| MITRE ATT&CK | Attack techniques & sub-techniques |
| CISA KEV | Known Exploited Vulnerabilities catalog |
| CWE / CAPEC | Weakness Enumeration / Attack Pattern Enumeration |
| D3FEND | Defensive countermeasure knowledge base |
| GitHub Advisory | GitHub security advisories |
| ZDI | Zero Day Initiative advisories |
| CVE / NVD | Common Vulnerabilities and Exposures / National Vulnerability Database |
| Exploit-DB | Exploit code repository |
| Linux Vulns | Linux kernel & distribution vulnerability tracking |

### Layer 4 Gap-Aware Dispatch

Reverse-engineers knowledge blind spots from Layer 1 failure annotations, triggering targeted crawls at P0 (immediate) / P1 (daily) / P2 (weekly) priorities:

```bash
python run/run_layer4_gap_dispatch.py
```

---

## Project Status

### Implemented

- Layer 0 log normalization (4 framework adapters, auto-detect log format)
- Layer 1 LLM batch annotation (15 sessions, 415 events, 171 failures, 5-dimension classification)
- Layer 2 experience distillation (rules + LLM, 172 artifacts, 5 knowledge types)
- Layer 3 XPEC cross-session fusion (SEC/EWC/RME/BCC/KLM, 137 KLM entries, 55 conflicts)
- Layer 4 gap-aware crawling framework (7 gap dimensions, P0/P1/P2 scheduling)
- RAGFlow reflow (6 high-confidence KLM entries synced)
- Multi-source crawler framework (5 sources + 11 external databases)
- Web Dashboard (full pipeline trigger, knowledge health, gap analysis, crawler management)
- pytest test suite (276 test cases)

### In Progress

- RAGFlow batch sync (goal: all KLM entries synced to RAGFlow)
- Layer 4 scheduler stability improvements

---

## Dashboard Overview

The Dashboard uses a "top status bar + left navigation + main workspace" layout, organized by "Experience Library, Analysis, Fusion, Knowledge Base" sections, covering the complete business chain of collection, distillation, governance, and reflow.


### Overview & Statistics

Displays total experience count, five knowledge type counts, session count, and charts for knowledge layer distribution, session outcome distribution, confidence distribution, target service distribution, and attack phase distribution.


### Five Experience Libraries

FACTUAL, PROCEDURAL_POS, PROCEDURAL_NEG, METACOGNITIVE, CONCEPTUAL — each with independent paginated browsing, keyword search, and experience cards showing exp_id, confidence, target service, CVE tags, extraction source, and summary.


### Experience Detail Modal

Click any experience card to view metadata (source session, outcome, confidence, extraction method, target service, CVE, creation time) and layer-specific content: FACTUAL provides findings + original evidence; PROCEDURAL_NEG provides failed commands, failure mode, decision rules, fix suggestions; PROCEDURAL_POS provides parameterized command templates, success evidence, preconditions, follow-up actions; METACOGNITIVE & CONCEPTUAL show lessons learned, core insights, and trigger conditions.


### Session Browser & Review

Session-centric view showing target service, CVE, attack outcome, experience count, and layer distribution — providing a process-oriented perspective for reviewing individual penetration test knowledge quality.


### Staged Pipeline & Real-time Logs

Layer 0 through Upload staged execution with select/deselect all, skip upload, detailed logs, status reset, and SSE-based real-time stage status, duration, and current step display. The top bar provides a one-click "Start Reflection" button to trigger the core distillation pipeline.


### Crawler Management

Full lifecycle coverage of collection, sync, and cleanup:
- **WeChat Official Accounts**: seed account management, Sogou/native dual-mode, mitmdump proxy integration, article preview
- **Web Crawlers**: multi-source (CSDN/GitHub/Qi-AnXin/XianZhi) keyword/CVE-driven crawling
- **RSS Auto-Subscription**: status display and manual sync
- **External KB Sync**: 11 databases with selective sync per repository
- **RAG Source File Management**: cleanup by source, file, or full level


### Layer 3 Fusion, Knowledge Health & Gap Analysis

Top section visualizes "Raw Experience → SEC Clustering → Rule Fusion → Confidence Calibration → Authoritative Knowledge" with compression ratio, maturity, and average fusion confidence metrics. Bottom section shows lifecycle distribution and conflict entries in "Knowledge Health", and gap score with one-click targeted crawling in "Gap Analysis".


### RAGFlow Integration & Reflow

Displays integration status with the external RAGFlow retrieval platform, providing a one-click jump entry and integration notes. High-value fused experiences reflow to the vector database, serving as a callable knowledge base for downstream intelligent Q&A and agent decision support.


Start:

```bash
cd dashboard
python app.py
```

Visit: http://localhost:5000

---

## Project Structure

```
.
 configs/
 crawlers/
 dashboard/
 data/
 docs/
 run/
 src/
 lore.py
```

---

## Documentation Index

- `docs/01_OVERVIEW.md`: project overview
- `docs/02_ARCHITECTURE.md`: architecture
- `docs/03_USAGE_GUIDE.md`: deployment and troubleshooting

---

## FAQ

Q: Why don't I see CONCEPTUAL artifacts in meta_conceptual?

A: Check routing: CONCEPTUAL -> dataset_metacognitive. By default CONCEPTUAL is routed into the metacognitive dataset.

Q: What to do about intermittent 502s when uploading to RAGFlow?

A: Use retry flags:

```bash
python -m src.ragflow.uploader --source fused --retry-502-max 8 --retry-base-sec 2.0
```

---

## Development & Testing

Run tests:

```bash
pytest -q
```

Recommended flow:

1. Validate single-stage outputs
2. Run `run/run_full_pipeline.py` for integration
3. Upload and verify with Dashboard

---

## Security & Compliance

This project is intended for authorized security research, testing, and education only. Do not use it against systems without explicit permission.

---

## License

MIT License. See LICENSE file.
