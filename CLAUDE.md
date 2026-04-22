# CLAUDE.md

## Behavioral Guidelines

Behavioral guidelines to reduce common LLM coding mistakes. 

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them. Don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it. Don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

## Project Overview: Optimus

**Optimus** is a unified pentesting automation platform that combines the best of three prior projects: KB Builder (scope management & execution), TopAgent (reporting & tool orchestration), and Agent-Nimi (provider flexibility & self-improvement). It is database-first, MITRE ATT&CK-organized, and optimized for token economy and playbook-driven fast execution.

### Non-Negotiable Principles

1. **DB-first, no LLM until needed**: All tool/skill lookup is programmatic (FTS5 search). LLM is only invoked when planning or replanning.
2. **MITRE ATT&CK as organizing spine**: Every tool in `kali_tools.db` is mapped to an attack phase. Tool retrieval filters by `attack_phase` first.
3. **Playbooks by default**: Straight, fast execution path for known attacks (Tier 1: passive/reconnaissance). Deep research (`kb agent_init`) only on demand.
4. **Single LLM provider**: Config value only (`grok`, `claude`, `groq`, `openai`). No router, no fallback chain. Provider is pluggable but never dynamic.
5. **Token economy**: 4000-token budget per executor step. Tool context is compact (~800 tokens). Output parsed before re-feeding to LLM.
6. **Self-improving**: Successful runs appended to `artifacts/playbooks/` as new recipes. Tool success_rate (EWMA) updated after each use.

### Project Structure

```
optimus/
├── pyproject.toml                 # name=optimus, entry: kb=kb.cli:main
├── alembic.ini & alembic/         # database migrations
│
├── kb/
│   ├── cli.py                     # typer app: sync, agent_init, run, doctor
│   ├── ingesters/                 # 10 data sources (MITRE, NVD, CISA, OTX, VT, Shodan, etc.)
│   │   └── mitre_attck.py        # CRITICAL: maps tools to attack_phase via attackcti
│   └── compiler.py                # synthesizes playbook YAML from KB research
│
├── core/
│   ├── prompt_analyzer.py         # extract intent, domain, targets (programmatic)
│   ├── tool_retriever.py          # FTS5 + attack_phase filter + success_rate re-rank
│   ├── planner.py                 # LLM call #1 → Pydantic JSON to-do list
│   ├── executor.py                # runs tool argv (shell=False, scope-checked)
│   ├── output_parser.py           # tool-specific parsers (nmap XML, gobuster, etc.)
│   ├── replanner.py               # LLM call #2 on failure; Lluminate strategies attempt 3+
│   ├── reflect.py                 # successful run → new recipe in artifacts/
│   ├── scope.py                   # target scope validation (from KB Builder)
│   ├── session.py                 # session state + token budget tracking
│   └── steer.py                   # mid-run steering: steer_queue for prompt injection
│
├── db/
│   ├── tool_db.py                 # kali_tools.db: FTS5, EWMA scores, success_rate
│   ├── session_db.py              # pentest.db: sessions, steps, vulnerabilities
│   └── scanner.py                 # walks dpkg -l + man pages → seeds kali_tools.db
│
├── provider.py                    # single configurable LLM class (Grok/Claude/Groq/OpenAI)
│
├── reporting/
│   └── report_generator.py        # Markdown/HTML from session DB (from TopAgent)
│
├── web/
│   ├── server.py                  # Flask app factory
│   ├── blueprints/
│   │   ├── chat.py                # / — main chat + thoughts drawer
│   │   ├── kb_research.py         # /kb — subject → animated SVG pipeline + SSE
│   │   ├── run.py                 # /run — playbook exec + steering overlay
│   │   ├── tools.py               # /tools — FTS5 browser + attack_phase filter
│   │   ├── db_editor.py           # /db — inline table editor
│   │   ├── sessions.py            # /sessions/<id> — step-by-step detail
│   │   ├── reports.py             # /reports/<id> — HTML pentest report
│   │   ├── settings.py            # /settings — provider/model, token budget, ingester toggles
│   │   └── sync.py                # /api/sync — trigger kb sync
│   └── templates/
│       ├── base.html              # sidebar + agent-status drawer
│       ├── chat.html              # main chat + live thoughts panel
│       ├── kb_research.html       # animated pipeline infographic
│       ├── run.html               # SSE output + steering overlay
│       └── db_editor.html         # tabbed table browser
│
├── config/
│   ├── config.yaml                # runtime config: provider, model, token budget, scope file paths
│   ├── policies.yaml              # Tier 1/2/3 definitions (from KB Builder)
│   ├── domain_taxonomy.yaml       # keyword → domain mapping for PromptAnalyzer
│   └── scope/
│       └── example/scope.yaml     # per-project target scope
│
└── artifacts/
    ├── playbooks/                 # YAML playbooks (pre-built + reflect_on_run output)
    └── review_queue/              # Tier 3 candidates awaiting human review
```

### Commands

#### Core CLI (entrypoint: `kb` from `pyproject.toml`)

```bash
# Sync all 10 ingesters → update kali_tools.db with latest tools, CVEs, techniques
kb sync

# Deep research: KB agent runs 10 ingesters → synthesizes new playbook YAML
kb agent_init "SMB vulnerabilities 2025"

# Execute a playbook against a target
kb run <playbook_name> --target <ip_or_domain> [--tier 1|2|3]

# Diagnostic: check DB health, LLM key, scope files, tool install status
kb doctor
```

#### Development / Testing

```bash
# Install in editable mode
pip install -e .

# Database migrations
alembic upgrade head
alembic downgrade -1

# Run tests (if test suite exists)
pytest tests/ -v

# Format & lint
black kb/ core/ db/ web/ --line-length 100
ruff check kb/ core/ db/ web/ --fix
```

#### Web UI (requires Flask)

```bash
# Start development server (or run via Procfile/gunicorn in prod)
python -m flask --app web.server run --debug
# Opens http://localhost:5000
```

### Database Schema

#### kali_tools.db (tool inventory)

```sql
CREATE TABLE kali_tools (
    id INTEGER PRIMARY KEY,
    tool_name TEXT UNIQUE NOT NULL,
    category TEXT,
    attack_phase TEXT,          -- MITRE ATT&CK phase (reconnaissance, initial-access, etc.)
    one_line_desc TEXT,
    syntax_template TEXT,       -- e.g. "nmap -sV {target}"
    man_page_compressed TEXT,
    tags TEXT,                  -- "recon,port,tcp,udp"
    tier INTEGER DEFAULT 1,     -- 1=passive, 2=active, 3=destructive
    pkg_name TEXT,              -- for auto-install
    installed BOOLEAN DEFAULT 1,
    success_rate REAL DEFAULT 0.5,  -- EWMA, updated after each use
    use_count INTEGER DEFAULT 0,
    embedding BLOB,             -- optional: for ChromaDB / sqlite-vec
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE VIRTUAL TABLE kali_tools_fts USING fts5(
    tool_name, tags, one_line_desc, man_page_compressed,
    content='kali_tools', content_rowid='id'
);
CREATE INDEX idx_attack_phase ON kali_tools(attack_phase);
```

#### pentest.db (execution history & findings)

```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    project_id TEXT,
    playbook TEXT,
    target TEXT,
    tier INTEGER,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    outcome TEXT  -- success/partial/stuck
);

CREATE TABLE steps (
    id INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id),
    step_num INTEGER,
    goal TEXT,
    tool_used TEXT,
    args TEXT,          -- JSON
    raw_output TEXT,
    parsed_output TEXT, -- JSON structured result (never raw multi-KB text)
    outcome TEXT,       -- success/fail/stuck
    attempt_count INTEGER DEFAULT 1
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id),
    cve_id TEXT,
    tool_used TEXT,
    severity TEXT,
    attack_technique TEXT,   -- MITRE ATT&CK technique ID
    loot TEXT
);
```

### Execution Flow

1. **SCOPE CHECK** (zero LLM): Validate target against `scope.yaml` via `core/scope.py`.
2. **TOOL LOOKUP** (zero LLM): FTS5 + `attack_phase` filter on `kali_tools.db` → compact tool context (~800 tokens).
3. **LLM CALL #1 — PLAN**: Pydantic-validated JSON to-do list → `[{step, goal, tool, args, success_criteria}]`.
4. **EXECUTE LOOP** (step by step):
   - Run tool via argv-only executor (no `shell=True`).
   - **Parse output** before re-feeding LLM (structured JSON, not raw text).
   - Score: exit_code + pattern match against success_criteria.
   - If **SUCCESS**: mark done, continue.
   - If **FAIL (attempts 1–2)**: LLM CALL #2 (minimal context, suggest alternate tool).
   - If **FAIL (attempt 3+)**: **Creative Divergence** (Lluminate-based strategy selected by failure context).
   - If iteration > 5 and tier < 3: auto-escalate to next tier.
5. **REFLECT + IMPROVE**: On success, append new recipe to `artifacts/playbooks/` and update EWMA scores.

### Creative Divergence (Lluminate-based Replanning)

Engaged only at attempt 3+ (never on attempts 1–2). Strategy is **programmatic** (no LLM) and injected as reasoning prefix:

| Failure Context | Strategy | Injection |
|---|---|---|
| Multiple tools from same attack phase all failed | Forced Connections | "Approach this step as if you were in a completely different attack phase…" |
| Tool found, but arg/flag combination failing | SCAMPER | "Substitute the current flag set. Combine with different output format…" |
| Expected service/port absent | Assumption Reversal | "List every assumption about this target. Now reverse each one…" |
| All other stuck cases | Oblique Strategies | Random hint from 10 pre-written lateral prompts |

The strategy framing does **not** change the output schema (still strict JSON); temperature stays 0.7.

### Key Design Patterns

#### No LLM for Tool Lookup
Always use `core/tool_retriever.py` with FTS5 + `attack_phase` filter. Do not ask LLM "which tools should I use?"

#### Compact Tool Context
Tool context block (fed to planner.py) is ~800 tokens max:
```json
[
  { "name": "nmap", "syntax_template": "nmap -sV {target}", "one_liner": "Port scan with service detection", "tier": 1, "attack_phase": "reconnaissance" },
  { "name": "gobuster", "syntax_template": "gobuster dir -u {target} -w {wordlist}", "one_liner": "Web directory brute force", "tier": 2, "attack_phase": "discovery" }
]
```

#### Structured Output Parsing
**Always** parse tool output via `core/output_parser.py` before feeding to LLM:
- `nmap -oX` → `{hosts, ports, services}` (structured dict)
- `gobuster` → `{found_paths}` (line-by-line parsed)
- `nikto` (CSV) → `{findings, severity}`
- Fallback: regex extraction (IP, URL, CVE patterns)

Feed **parsed JSON**, never raw multi-KB output.

#### Token Budget Enforcement
- Per-step budget: 4000 tokens (configurable in `/settings`)
- Tracked in `core/session.py`
- Planner.py receives budget as constraint
- If budget exceeded: fail the step, trigger replanner

#### Scope Validation (Immutable)
`core/scope.py` (ported from KB Builder) validates target before ANY execution. Tier escalation cannot override scope.

#### No Shell=True
grep for `shell=True` in `core/`, `db/`, `executor.py` must yield zero matches. All tool invocation is argv-only via `subprocess.run([...], shell=False)`.

### Output Parsing Layer

Create tool-specific parsers in `core/output_parser.py`:

```python
class OutputParser:
    PARSERS = {
        "nmap": parse_nmap_xml,       # parse -oX output
        "gobuster": parse_gobuster,   # line-by-line
        "nikto": parse_nikto,         # csv
        "sqlmap": parse_sqlmap,       # regex
    }

    def parse(self, tool: str, raw: str) -> dict:
        parser_fn = self.PARSERS.get(tool, self.generic_parse)
        return parser_fn(raw)  # always returns structured dict
```

Results stored in `steps.parsed_output` (JSON), fed to LLM as compact summary.

### LLM Provider Configuration

Single provider class (`provider.py`), config-driven. In `config/config.yaml`:

```yaml
llm_provider: "grok"           # or "claude", "groq", "openai"
llm_model: "grok-3"            # set dynamically based on provider
api_key: "${GROK_API_KEY}"     # read from env or .env
base_url: null                 # optional override for local Ollama
```

No router, no fallback chain. Changing provider requires config edit + server restart.

### Web UI ("Spectral Analyst" Aesthetic)

#### Design System
- Fonts: **Syne** (headers), **Epilogue** (body), **Iosevka** (monospace/code)
- Palette: warm obsidian (#0C0A09) + terracotta accents (#C44B22) + gold highlights (#D4A843)
- No Bootstrap. Pure CSS Grid + Flexbox.
- Animations: staggered reveals, heartbeat pulse (active steps), typewriter (chat messages), scan-line effects (data panels)

#### Key Pages
- **`/`** — Main chat interface + thoughts drawer (token gauge, plan accordion, strategy badge)
- **`/kb`** — KB research UI: subject prompt + animated SVG pipeline (4-node flow diagram) + per-source progress bars + live log + cancel/pause
- **`/run`** — Playbook executor: SSE output pane + steering overlay (mid-run prompt injection)
- **`/tools`** — FTS5 tool browser: search by keyword + attack_phase filter
- **`/db`** — Database editor: tabbed table view, inline row editing (PUT/DELETE), add-row modal
- **`/settings`** — Provider/model dropdowns (JS dynamic), API key fields (masked), token budget slider, tier radio, ingester toggles + save

#### SSE Streaming
- Chat: agent responses streamed as they arrive
- KB Research: per-stage progress (fetch/parse/extract/store), animated node pulses
- Playbook Run: step-by-step output + token usage updates

### Self-Improvement: reflect_on_run()

After a successful session:

1. **Build recipe YAML** from the successful steps (tool sequences, arguments, success patterns).
2. **Append to `artifacts/playbooks/`** as a new playbook.
3. **Update EWMA scores** in `kali_tools.db` for every tool used:
   - Success: `success_rate += (1 - success_rate) * 0.1`
   - Failure: `success_rate -= success_rate * 0.1`

Next run: tool retrieval weighted by `success_rate`, so proven-effective tools bubble up.

### What NOT to Do (Anti-Patterns)

- ❌ Ask LLM to choose tools. Use FTS5 + attack_phase filter programmatically.
- ❌ Feed raw multi-KB tool output to LLM. Always parse to structured JSON first.
- ❌ Use `shell=True` in executor. Always use argv-only `subprocess.run([...], shell=False)`.
- ❌ Multi-LLM routing or fallback chains. Single provider, config-driven. Pick one and commit.
- ❌ Multiagent roles / orchestrator patterns. One LLM, one session, one to-do list.
- ❌ Dynamic provider switching. No SmartRouter. Provider is a config value.
- ❌ Store raw session outputs in DB. Always parse tool output to structured `{key: value}` dicts.

### Component Sources

| Module | Source | Action |
|--------|--------|--------|
| `core/executor.py` | KB Builder `gateway/executor.py` | Port verbatim (argv-only) |
| `core/scope.py` | KB Builder `gateway/scope.py` | Port verbatim |
| `config/policies.yaml` | KB Builder | Port verbatim |
| `db/session_db.py` schema | TopAgent `db/schema.py` | Port + extend (add steps, vulns) |
| `reporting/report_generator.py` | TopAgent | Port as-is |
| `web/` (Flask + SSE) | Agent-Nimi | Port + simplify (remove multi-provider blueprints) |
| `core/reflect.py` EWMA logic | Agent-Nimi `core/memory.py` | Extract EWMA logic only |
| `provider.py` | Agent-Nimi `providers/grok.py` | Flatten to single configurable class |

### Verification Checklist

- ✓ `kb sync` runs without error; `kali_tools` table has `attack_phase` populated
- ✓ `db/tool_retriever.py` search "web directory brute force" returns `gobuster`, `dirb`, `ffuf` (no LLM)
- ✓ `kb run recon --target 10.0.0.1` → plan created with 1 LLM call; nmap output parsed to JSON
- ✓ Target outside scope → blocked before execution
- ✓ Force tool failure → replanner suggests alternate; attempt 3+ → creative divergence fires (correct strategy)
- ✓ After success: new YAML in `artifacts/playbooks/`; tool `success_rate` updated in DB
- ✓ `grep -r "shell=True" core/ db/` → zero matches
- ✓ Token usage per step logged; stays under 4000-token budget
- ✓ Web aesthetic: Syne headers, Epilogue body, terracotta accents, no Bootstrap
- ✓ Chat: send message → AI responds; start playbook → thoughts drawer slides in, token gauge updates live
- ✓ Mid-run steering: click [⊗ Steer Run], submit "focus on port 443" → agent adjusts remaining plan
- ✓ KB Research: enter subject, click BEGIN → SVG pipeline animates, MITRE node pulses, progress reaches 100%
- ✓ DB Editor: GET /db shows table; click ✎ on row → cells become inputs; save → reflects change; click ✕ → deleted
- ✓ Settings: switching provider to groq updates model dropdown without page reload; save → config.yaml + .env updated

### Implementation Phases (Reference)

**Phase 1**: DB foundation (scanner.py, MITRE mapping, FTS5, EWMA fields)  
**Phase 2**: Prompt → Plan pipeline (prompt_analyzer, tool_retriever, planner, provider)  
**Phase 3**: Execution + parsing + replanning (executor, output_parser, replanner with Lluminate)  
**Phase 4**: Self-improvement + remaining ingesters (reflect.py, all 10 ingesters, agent_init flow)  
**Phase 5**: Web UI + reporting (Flask blueprints, SSE, "Spectral Analyst" aesthetic, all settings)
