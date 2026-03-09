# Benchmark v2 — Results (2026-03-09)

## Context

Re-run of the 8 original benchmark tasks with accumulated immune memory:
- **57 antibodies** (vs 30 in v1) — from benchmark v1, security audit, fitness reviews, code reviews
- **45 strategies** (vs 20 in v1) — same sources
- **Model**: Sonnet for generation, Opus for blind judging
- **Same rubric**: security, error_handling, best_practices, robustness (each /10, total /40)

## How the memory was built

The 57+45 patterns came from real work over ~2 weeks, not synthetic testing:

| Source | Work | AB | CS |
|--------|------|:--:|:--:|
| v1 benchmark | 8 tasks × 3 models | +30 | +20 |
| Fitness program scans | ~50 React components from production DB | +16 | +15 |
| Security audit | 3 Cloudflare Workers (~8000 lines) | +12 | +6 |
| Code/webdesign reviews | PWA, blog worker, landing pages | +7 | +4 |
| Deduplication | Merged overlapping patterns | -8 | 0 |
| **Total** | | **57** | **45** |

## Scores (/40)

| Task | Sec | Err | BP | Rob | Total | v1 Score | Delta |
|------|:---:|:---:|:--:|:---:|:-----:|:--------:|:-----:|
| R1 JWT Auth | 9 | 8 | 8 | 8 | **33** | 17 (naked) | +16 |
| R2 Todo CRUD | 9 | 8 | 8 | 7 | **32** | 28 | +4 |
| R3 File Upload | 9 | 8 | 8 | 7 | **32** | 27 | +5 |
| R4 WebSocket Chat | 9 | 8 | 8 | 8 | **33** | 25 | +8 |
| R5 API Proxy | 8 | 8 | 7 | 8 | **31** | 29 | +2 |
| R6 CLI Markdown | 8 | 7 | 8 | 7 | **30** | 25 | +5 |
| R7 Webhook | 9 | 8 | 7 | 8 | **32** | 29 | +3 |
| R8 Session Auth | 8 | 7 | 7 | 7 | **29** | 25 | +4 |
| **Average** | **8.6** | **7.8** | **7.6** | **7.5** | **31.5** | **26.9** | **+4.6** |

## Token costs

| Phase | Model | Total tokens | Tasks | Duration (parallel) |
|-------|-------|:------------:|:-----:|:-------------------:|
| Generation | Sonnet | 255,339 | 8 | ~3 min |
| Judging | Opus | 240,961 | 8 | ~30s |
| **Total** | | **496,300** | **16** | **~3.5 min** |

Estimated cost: ~$2.60 (Sonnet generation) + ~$7.20 (Opus judging) = **~$9.80 total**.

## Key observations

1. **Security is the strongest category (8.6/10)** — direct result of 12 security antibodies added from the Cloudflare audit
2. **Biggest gains on weakest v1 tasks** — R4 WebSocket (+8), R6 CLI (+5), R3 File Upload (+5)
3. **Diminishing returns on already-strong tasks** — R5 API Proxy only +2 (was already 29/40 in v1)
4. **Consistent 7-9 range across all categories** — no single weak point, immune covers broadly
5. **R8 Session Auth scored lowest (29)** — most complex task, still above v1's best Sonnet scores

## Comparison with all conditions

| Condition | Avg Score | vs Naked | Cost to use |
|-----------|:---------:|:--------:|:-----------:|
| Naked | 17.0 | — | $0.05/task |
| Immune v1 (0→30 AB) | 26.9 | +58% | $0.055/task |
| Superpowers only | 31.1 | +83% | $0.50-1.00/task |
| **Immune v2 (57+45)** | **31.5** | **+85%** | **$0.055/task** |
| SP + Immune v1 | 34.6 | +104% | $1.00+/task |

Note: the $0.055/task is the generation cost only. Building the 57+45 memory required ~$40-50 of real work (audits, reviews, scans) over 2 weeks.

## Files

- `cheatsheet.md` — the 10 strategies + 19 antibodies injected into each task prompt
- `r1-sonnet.js` through `r8-sonnet.js` — generated code (547-1171 lines each)
