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

### Comparison: Immune vs Superpowers vs Both

We also compared immune against the [Superpowers](https://github.com/anthropics/claude-code-plugins) methodology plugin, using Sonnet for all conditions:

| Condition | Avg Score | vs Naked |
|-----------|:---------:|:--------:|
| Naked (Sonnet) | 17.0 | — |
| Immune only | 26.9 | **+58%** |
| Superpowers only | 31.1 | **+83%** |
| **SP + Immune** | **34.6** | **+104%** |

- **SP+Immune is the best condition** — doubling the naked baseline
- **Superpowers alone outperforms Immune alone** (+16%) — methodology principles (SRP, DRY, YAGNI) have high baseline impact
- **Immune adds +11% on top of SP** — the combination is additive, not redundant
- **Security (+1.3pp) and Robustness (+1.4pp)** are where immune adds the most value over superpowers alone
- **SP+IM achieves 36/40 consistently from R4+** — immune stabilizes quality near the ceiling

See [`benchmark/comparison/results.md`](benchmark/comparison/results.md) for full breakdown.

### Token Cost Analysis

Every quality improvement has a cost. Here's what each point of improvement actually costs in tokens:

| Condition | Total tokens (8 rounds) | Improvement | Cost per point |
|-----------|:-----------------------:|:-----------:|:--------------:|
| Superpowers only | ~61k | +14.1 pts (17→31.1) | **~4,300 tokens/point** |
| SP + Immune | ~92k | +17.6 pts (17→34.6) | **~5,200 tokens/point** |
| Immune marginal cost | +31k | +3.5 pts (31.1→34.6) | **~8,900 tokens/point** |

The first points are cheap, the last ones cost 2x more — classic diminishing returns. But those last 3.5 points are almost entirely in **security** (+1.3pp) and **robustness** (+1.4pp), which are the most critical categories in production code.

```
Cost per point vs quality level:

  tokens/pt
  9000 ─┤                              ╭── Immune marginal
  8000 ─┤                             ╱    (+3.5 pts in security
  7000 ─┤                            ╱      & robustness)
  6000 ─┤                           ╱
  5000 ─┤              ╭── SP+IM ──╯
  4000 ─┤    ╭── SP ──╯
  3000 ─┤   ╱
  2000 ─┤  ╱
  1000 ─┤ ╱
     0 ─┤╱
        └──────────────────────────────────
        17    22    27    31   34.6  /40
              Quality score →
```

**Where the tokens go:**
- **Superpowers** adds ~2,500 input tokens/round (static methodology injection — same cost every round)
- **Immune cheatsheet** adds ~900 input tokens/round (grows with learned strategies)
- **Immune scan** adds ~1,700 tokens/round (Haiku scan prompt + response — cheapest model)
- **Output grows** with quality: SP+IM generates ~27% more code than SP alone (more validation, error handling, security headers)

**The ROI argument:** A single security vulnerability in production costs orders of magnitude more than 31k tokens. The immune's marginal cost targets exactly the categories (security, robustness) that cause the most expensive production incidents.

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

- **37 antibodies** = 37 mistakes someone already made and corrected
- **33 strategies** = 33 winning patterns validated in production

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
