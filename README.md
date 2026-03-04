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

## Benchmark: ImmuneEval+

Run `/immune-eval` to measure detection accuracy and learning progression across 40 test cases in 4 batches. Tracks Recall, Precision, F1, and learning rate per batch.

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
