# Immune System v3 — Hybrid Adaptive Memory for Claude Code

A Claude Code skill that makes any LLM output better over time through two complementary memories:

- **Cheatsheet** (positive patterns): Domain-specific winning strategies injected *before* generation
- **Immune** (negative patterns): Error detection antibodies applied *after* generation

Both memories use **Hot/Cold tiering** to keep context lean, and **learn automatically** from every scan.

## How It Works

```
[User Request]
  --> Step 0: Inject cheatsheet strategies (positive patterns)
  --> Step 1: Generate output (with cheatsheet context)
  --> Step 2: Immune scan (detect known + new errors)
  --> Step 3: Fix errors + learn new antibodies
  --> Step 3b: Detect + learn new winning strategies
```

The system improves with usage. Each scan can discover new antibodies (things to avoid) and new strategies (things to repeat). These persist across sessions.

## Key Features

- **Dual memory**: Separate files for antibodies (`immune_memory.json`) and strategies (`cheatsheet_memory.json`) — never combined in the same prompt
- **Hot/Cold tiering**: Active patterns sent in detail, dormant ones as keywords. Keeps Haiku's context under ~400 tokens typical
- **Multi-domain**: `domains: ["fitness", "code"]` — match antibodies/strategies across multiple domains simultaneously
- **Auto-learning**: New patterns discovered during scans are added automatically
- **COLD reactivation**: Dormant patterns reactivate when re-detected
- **Strategy pruning**: Low-effectiveness strategies are auto-removed after enough data
- **3 modes**: `full` (cheatsheet + scan), `scan-only`, `cheatsheet-only`
- **Backwards compatible**: Reads v2 memory files and auto-migrates

## Usage

```
/immune Check this function for pitfalls
/immune domain=fitness Verify this workout program
/immune domains=fitness,code Check this workout API endpoint
/immune                          # scans last output in conversation
```

## Domains

Pre-configured: `fitness`, `code`, `writing`, `research`, `strategy`, `webdesign`, `_global`

Add custom domains by editing `config.yaml` → `domain_keywords`.

## Benchmark: Learning Curve

**Does immune actually improve code quality?** We tested it across 8 real-world coding tasks, 3 models, and 24 blind judgments.

### Protocol

1. Reset immune memory to 0
2. Round 1: Generate code **without** immune (baseline)
3. Rounds 2-8: Inject learned cheatsheet strategies **before** generation, scan **after**, learn new patterns
4. Judge (Opus) scores blind on /40: security, error handling, best practices, robustness

### Results

| Model | Baseline (R1) | With Immune (avg R2-R8) | Improvement |
|-------|:---:|:---:|:---:|
| **Haiku** | 19/40 | 22.3/40 | **+17%** |
| **Sonnet** | 17/40 | 26.9/40 | **+58%** |
| **Opus** | 18/40 | 26.7/40 | **+48%** |

### Score Progression

```
     R1    R2    R3    R4    R5    R6    R7    R8
     (0)  (+3)  (+8) (+10) (+15) (+20) (+20) (+20) strategies
      │     │     │     │     │     │     │     │
  31 ─┤     ·     ·     ·     *     ·     ·     ·   Opus peak
  29 ─┤     ·     ·     ·     *     ·     *     ·   Sonnet peaks
  27 ─┤     **    **    *     ·     ·     ·     ·
  25 ─┤     *     *     *     *     **    *     **
  23 ─┤     ·     *     ·     ·     *     *     *
  21 ─┤     ·     ·     ·     ·     ·     ·     ·
  19 ─┤     *     ·     ·     *     ·     ·     ·   Haiku baseline
  17 ─┤     *     ·     ·     ·     ·     ·     ·   Sonnet baseline
      └─────┴─────┴─────┴─────┴─────┴─────┴─────┘
```

### Key Findings

- **Sonnet benefits most** (+58%): Mid-tier models are the sweet spot — strong enough to follow strategies, weak enough to need them
- **Knowledge transfers across domains**: Strategies from auth code improved WebSocket, proxy, and webhook code
- **30 antibodies + 20 strategies** learned in 8 rounds, with diminishing returns around round 5
- **Best single score**: Opus at 31/40 on API proxy task (R5)

Open [`benchmark/viewer.html`](benchmark/viewer.html) for interactive charts, or see [`benchmark/results.md`](benchmark/results.md) for the full data.

### Benchmark v2: Accumulated Memory (57 AB + 45 CS)

The v1 benchmark started from zero and learned 30 antibodies + 20 strategies over 8 rounds. But that's an artificial setup — in practice, immune memory is built through real work over time.

**How the 57+45 memory was actually built:**

| Phase | Work done | AB learned | CS learned |
|-------|-----------|:----------:|:----------:|
| v1 benchmark | 8 coding tasks × 3 models, blind judging | +30 | +20 |
| Fitness program reviews | Scanned ~50 React programs from Smart Rabbit (1000+ profiles DB) | +16 | +15 |
| Security audit | Manual audit of 3 Cloudflare Workers (~8000 lines), then `/immune scan` on findings | +12 | +6 |
| Code reviews | PWA review, blog worker review, webdesign scans | +7 | +4 |
| Writing scans | Blog articles, technical documentation, benchmark writeup itself | -8 (deduplicated) | 0 |
| **Total** | | **57** | **45** |

This took ~2 weeks of real usage. The memory doesn't appear by itself — you have to scan real outputs, review real code, audit real infrastructure. Each task teaches immune something new.

We re-ran the same 8 benchmark tasks with Sonnet using this accumulated memory:

| Task | Naked | Immune v1 (0→30) | Immune v2 (57+45) | Delta v1→v2 |
|------|:-----:|:----------------:|:-----------------:|:-----------:|
| R1 JWT Auth | 17 | — (baseline) | **33** | — |
| R2 Todo CRUD | — | 28 | **32** | +4 |
| R3 File Upload | — | 27 | **32** | +5 |
| R4 WebSocket | — | 25 | **33** | +8 |
| R5 API Proxy | — | 29 | **31** | +2 |
| R6 CLI Markdown | — | 25 | **30** | +5 |
| R7 Webhook | — | 29 | **32** | +3 |
| R8 Session Auth | — | 25 | **29** | +4 |
| **Average** | **17.0** | **26.9** | **31.5** | **+4.6** |

Category breakdown (v2 averages):
- Security: **8.6**/10 — strongest, driven by 12 security-specific antibodies from the audit
- Error handling: **7.8**/10
- Best practices: **7.6**/10
- Robustness: **7.5**/10

See [`benchmark/run-v2/results.md`](benchmark/run-v2/results.md) for per-task judge details.

### Comparison: All Conditions

| Condition | Avg Score | vs Naked | Generation cost/task |
|-----------|:---------:|:--------:|:--------------------:|
| Naked (Sonnet) | 17.0 | — | ~$0.05 |
| Immune v1 (0→30 AB) | 26.9 | +58% | ~$0.055 |
| Superpowers only | 31.1 | +83% | ~$0.50-1.00 |
| **Immune v2 (57+45)** | **31.5** | **+85%** | **~$0.055** |
| **SP + Immune** | **34.6** | **+104%** | ~$1.00+ |

See [`benchmark/comparison/results.md`](benchmark/comparison/results.md) for the original SP vs SP+IM breakdown.

### Cost Analysis

**Generation cost** = what it costs to produce one piece of code with the cheatsheet injected. Immune adds ~1,500 input tokens (the cheatsheet) to the existing prompt — no extra API calls.

| | Generation overhead/task | Quality gain |
|---|:---:|:---:|
| Immune v2 | +$0.005 (1,500 tokens) | +14.5 pts (+85%) |
| Superpowers | +$0.50-1.00 (3-5 extra API calls) | +14.1 pts (+83%) |

**But this doesn't include the cost of building the memory.** The 57 antibodies and 45 strategies came from real work:
- v1 benchmark (8 rounds × 3 models + judging): ~$30-40
- Fitness program scans (~50 programs × Haiku scan): ~$2
- Security audit (3 agents × Opus): ~$5
- Code/writing reviews: ~$3-5

**Total investment to build the memory: ~$40-50 over 2 weeks.**

Once built, the memory is essentially free to use (~$0.005/task). The ROI depends on volume — at 1,000 generations, the amortized cost of building + using immune is ~$0.10/task vs $0.50-1.00/task for Superpowers.

### Accelerating Learning: Pair with Quality Tools

The fastest way to build immune memory is to **use it alongside high-performing tools** like [Superpowers](https://github.com/anthropics/claude-code-plugins) or Chimera:

1. Generate code with Superpowers (31/40 quality, ~$0.75/task)
2. Scan the output with `/immune` → learns winning strategies + catches remaining issues
3. Repeat 5-10 times across different tasks
4. Immune alone now produces 31.5/40 quality for $0.055/task

It's like training with a coach and then internalizing the lessons. The coach (Superpowers) costs $0.75/session, but once immune has absorbed the patterns, you get the same quality for $0.005/session.

In practice, our memory went from 0 to 57+45 in ~2 weeks by combining:
- Superpowers code generation → immune scan (learned code structure patterns)
- Security audit findings → immune scan (learned 12 security antibodies in one session)
- Fitness program reviews → immune scan (learned domain-specific React patterns)

Each scan with a quality tool teaches immune 2-5 new patterns. After ~20 scans, the memory plateaus and immune alone matches the tool's output quality.

### Tasks

| Round | Domain | Task |
|-------|--------|------|
| R1 | Backend auth | JWT auth API (Express, bcrypt) |
| R2 | Backend CRUD | Todo list API (filtering, pagination) |
| R3 | File handling | Image upload + thumbnail (multer, sharp) |
| R4 | WebSocket | Multi-room chat server (ws library) |
| R5 | Infrastructure | API proxy + circuit breaker + cache |
| R6 | Tooling | CLI markdown indexer + sitemap |
| R7 | Events | Webhook receiver + HMAC + retry |
| R8 | Security | Session auth + CSRF + brute-force protection |

## Why It Matters: Institutional Knowledge Transfer

The biggest value isn't the benchmark scores — it's **knowledge persistence across team changes**.

When a senior developer leaves, their hard-won knowledge leaves with them: "never do X on this project", "always check Y before deploying", "this API silently fails on Z". With immune, that knowledge lives in two JSON files:

- **57 antibodies** = 57 mistakes someone already made and corrected
- **45 strategies** = 45 winning patterns validated in production

A new team member runs `/immune` on their first code and immediately inherits months of accumulated domain expertise. Not a wiki nobody reads — patterns that **automatically inject** into the workflow.

| Traditional | With Immune |
|-------------|-------------|
| Knowledge in people's heads | Knowledge in `immune_memory.json` |
| Lost on employee turnover | Persists across team changes |
| Onboarding takes weeks | Day-1 access to all patterns |
| Same mistakes repeated | Each mistake caught once, prevented forever |
| Tribal knowledge, undocumented | Explicit, versioned, auditable |

## Architecture

Inspired by biological immune systems + Stanford's Dynamic Cheatsheet (2025):

| Concept | Biological Analog | Implementation |
|---------|------------------|----------------|
| Antibodies | Immune memory cells | `immune_memory.json` — error patterns |
| Strategies | Muscle memory | `cheatsheet_memory.json` — winning patterns |
| Hot/Cold | Active vs memory T-cells | Tiered by severity, frequency, recency |
| Reactivation | Immune recall response | COLD patterns reactivated on re-detection |
| Pruning | Apoptosis | Low-effectiveness strategies auto-removed |

## Token Budget

- Antibodies: max 15 hot x ~80 tokens = ~1,200 tokens (scan prompt only)
- Strategies: max 15 hot x ~60 tokens = ~900 tokens (generation prompt only)
- **Never combined** — cheatsheet at generation time, antibodies at scan time
- With domain filtering: ~400 tokens typical per injection

## Integration with Chimera

The immune system works standalone (`/immune`) or as Phase 3 of the [Chimera](https://github.com/contactjccoaching-wq/chimera) bio-inspired pipeline. When used with Chimera, cheatsheet strategies are injected into PRISM perspective prompts (Phase 0.5).

## License

MIT
