---
name: immune
description: "Adaptive memory system that makes any LLM output better over time. Learns what works (strategies) and what fails (antibodies) from every scan. Injects winning patterns before generation, catches errors after. Hot/Cold tiered memory with multi-domain support."
---

# Immune System v3 — Adaptive Memory for Claude Code

A skill that **learns from your real work** and makes every future generation better.

## What It Does

Two complementary memories that improve over time:

- **Cheatsheet** (positive patterns): Winning strategies injected *before* generation — like giving the model your team's best practices
- **Immune** (negative patterns): Error-detection antibodies applied *after* generation — catches mistakes the model keeps making

Both memories persist across sessions and learn automatically from every scan.

## Usage

```
/immune Check this function for pitfalls
/immune domain=fitness Verify this workout program
/immune domains=fitness,code Check this workout API endpoint
/immune                          # scans last output in conversation
```

### Modes

- `full` (default): Inject cheatsheet strategies + scan for errors + learn
- `scan-only`: Skip cheatsheet, just scan
- `cheatsheet-only`: Return strategies without scanning

### Domains

Pre-configured: `fitness`, `code`, `writing`, `research`, `strategy`, `webdesign`, `_global`

Add custom domains by editing `config.yaml` → `domain_keywords`.

## How It Works

```
[User Request]
  → Step 0: Inject cheatsheet strategies (positive patterns)
  → Step 1: Generate output (with cheatsheet context)
  → Step 2: Immune scan (detect known + new errors)
  → Step 3: Fix errors + learn new antibodies
  → Step 3b: Detect + learn new winning strategies
```

Each scan can discover new antibodies (things to avoid) and new strategies (things to repeat).

## Architecture

| Concept | Implementation |
|---------|---------------|
| Antibodies | `immune_memory.json` — error patterns with severity, domain, correction |
| Strategies | `cheatsheet_memory.json` — winning patterns with effectiveness score |
| Hot/Cold | Active patterns sent in detail, dormant ones as keywords (~400 tokens typical) |
| Reactivation | COLD patterns reactivate when re-detected |
| Pruning | Low-effectiveness strategies auto-removed after enough data |

## Benchmark Results

Tested across 8 real-world coding tasks with blind judging (Opus, /40 rubric):

| Condition | Avg Score | vs Baseline | Cost/task |
|-----------|:---------:|:-----------:|:---------:|
| Naked Sonnet | 17.0 | — | $0.05 |
| Immune v1 (30 AB + 20 CS) | 26.9 | +58% | $0.055 |
| **Immune v2 (57 AB + 45 CS)** | **31.5** | **+85%** | **$0.055** |

The memory was built through real work over ~2 weeks: benchmark rounds, security audits, code reviews, fitness program scans. Each scan teaches immune 2-5 new patterns.

## Installation

1. Copy the `skill/` folder to `~/.claude/skills/immune/`
2. Copy `skill/agents/immune-scan.md` to `~/.claude/agents/`
3. The memory files (`immune_memory.json`, `cheatsheet_memory.json`) start empty and learn from usage

## Token Budget

- Strategies: max 15 hot × ~60 tokens = ~900 tokens (generation prompt only)
- Antibodies: max 15 hot × ~80 tokens = ~1,200 tokens (scan prompt only)
- **Never combined** — cheatsheet at generation time, antibodies at scan time
- With domain filtering: ~400 tokens typical per injection

## Requirements

- Claude Code CLI
- A Haiku-capable agent slot (for the immune-scan agent)
- No external dependencies

## License

MIT
