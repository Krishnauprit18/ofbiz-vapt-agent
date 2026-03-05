# OFBiz VAPT Agent

An AI-powered security agent for vulnerability assessment and penetration testing of Apache OFBiz.
Uses a local LLM (DeepSeek-R1 via Ollama) with actual OFBiz source code context.

## Architecture — Two-Phase Design

The agent splits work into independent phases to reduce LLM overhead and give you full control:

```
Phase 1: ANALYZE          Phase 2: CHOOSE ONE
┌─────────────────┐       ┌──────────────────────┐
│ cli/analyze.py   │──────▶│ cli/reproduce.py     │ Reproduce + report
│                  │       │ cli/poc.py            │ PoC exploit only
│ LLM analysis +   │       │ cli/patch.py          │ Security patch + diff
│ codebase context │       └──────────────────────┘
└─────────────────┘
    Saves state → .vapt_state.json (Phase 2 reads from cache)
```

## Usage

### Phase 1: Analyze (always run first)
```bash
python3 cli/analyze.py "vulnerability description here"
```
- Searches OFBiz codebase for relevant files
- Runs LLM analysis → `vuln_understanding.md`
- Saves state so Phase 2 runs without re-doing analysis

### Phase 2: Choose your action

**Option A — Reproduce & Report** (needs OFBiz running):
```bash
python3 cli/reproduce.py --no-docker
```
Generates minimal test → runs against OFBiz → `reproduction_report.md`

**Option B — PoC Only** (no OFBiz needed):
```bash
python3 cli/poc.py
```
Generates `exploit.py` — does NOT execute. Review and run manually.

**Option C — Patch** (no OFBiz needed):
```bash
python3 cli/patch.py
```
Generates `security_fix.patch` — attempts `git apply` on OFBiz source.

### Deployment Modes

For `reproduce.py`, use `--no-docker` if OFBiz is already running (Kaggle/Colab):
```bash
python3 cli/reproduce.py --no-docker
```

Without the flag, it auto-deploys OFBiz via Docker.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OFBIZ_CODEBASE_PATH` | `/home/krishna/Pictures/ofbiz-framework` | Path to OFBiz source code |
| `PYTHONPATH` | — | Set to agent root dir |
