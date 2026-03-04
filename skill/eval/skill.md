---
name: immune-eval
description: "ImmuneEval+ benchmark runner. Measures immune system learning progression by running 4 batches of test cases from zero antibodies."
---

# ImmuneEval+ — Benchmark Runner

You run a standardized benchmark to measure the Immune System's detection accuracy and learning progression.

## Overview

The benchmark uses a dataset of 40 test cases split into 4 batches. The immune memory is reset to zero before starting. After each batch, new antibodies learned are kept — showing how the system improves over time.

## Execution Protocol

### Phase 0 — Setup

1. Read the dataset: `~/.claude/skills/immune/eval/dataset.json`
2. Read the current immune memory: `~/.claude/skills/immune/immune_memory.json`
3. Read the current cheatsheet memory: `~/.claude/skills/immune/cheatsheet_memory.json`
4. **Backup** both files by saving their full content (you'll restore them at the end)
5. **Reset** the immune memory file to:
```json
{"version": 3, "antibodies": [], "stats": {"outputs_checked": 0, "issues_caught": 0, "antibodies_total": 0}}
```
6. **Reset** the cheatsheet memory file to:
```json
{"version": 3, "strategies": [], "stats": {"outputs_assisted": 0, "strategies_applied": 0, "strategies_total": 0}}
```
7. Write both reset files

Log: `[EVAL] ImmuneEval+ starting | 40 cases | 4 batches | Memory reset to 0 antibodies + 0 strategies`

### Phase 1 — Run Batches

For each batch (1 through 4):

**Step 1.1 — Load current state**
- Read `~/.claude/skills/immune/immune_memory.json`
- Count current antibodies: `ab_before`
- Filter cases for this batch number

**Step 1.2 — Run scans**
For each case in the batch, spawn an `immune-scan` agent (Haiku) with:
```
DOMAIN: {case.domain}
TASK: Scan the following content for issues
CONSTRAINTS: none

CONTENT TO SCAN:
{case.input}

KNOWN ANTIBODIES:
{current antibodies filtered by case.domain + _global}

Scan the content for known patterns and new threats.
```

**CRITICAL: Launch ALL 10 agents for the batch IN PARALLEL** (single message, multiple Agent tool calls). This makes the benchmark fast.

Wait for all results.

**Step 1.3 — Score each case**

For each case, compare the agent's response to `expected_issues`:

**If `is_clean: true` (should NOT be flagged):**
- Agent returns `scan_result: "clean"` → **TN** (True Negative) ✓
- Agent returns corrections or threats → **FP** (False Positive) ✗

**If `is_clean: false` (has planted issues):**
For each expected issue:
- Issue detected (in `corrections_applied` or `new_threats_detected`, matching the pattern semantically) → **TP** (True Positive) ✓
- Issue NOT detected → **FN** (False Negative) ✗

**Semantic matching rules:**
- An expected issue is "detected" if the agent's correction/threat description addresses the same underlying problem, even if worded differently
- For `type: "known"` issues: check both `corrections_applied` AND `new_threats_detected`
- For `type: "novel"` issues: check `new_threats_detected`
- Be generous in matching — if the agent flags the correct category of problem, count it as TP

**Step 1.4 — Update memory**

Collect all `new_threats_detected` from all cases in this batch. For each unique new threat:
1. Add an antibody to `immune_memory.json`:
   - id: "AB-EVAL-{next_number}"
   - domain: from recommended_antibody
   - pattern, severity, correction: from the threat
   - seen_count: 1
   - first_seen / last_seen: today
2. Increment stats
3. Write back to `~/.claude/skills/immune/immune_memory.json`

Count antibodies after: `ab_after`

**Step 1.5 — Log batch results**

Calculate for this batch:
- **Recall** = TP / (TP + FN)
- **Precision** = TP / (TP + FP)
- **F1** = 2 × P × R / (P + R) (if P + R = 0, F1 = 0)

Log:
```
[EVAL] Batch {n}/4 complete | Recall: {R}% | Precision: {P}% | F1: {F1}% | AB: {ab_before}→{ab_after}
```

Log each case result:
```
  {id} [{domain}] {difficulty} — {PASS|FAIL} {details}
```

### Phase 2 — Final Scorecard

After all 4 batches, present the full results:

```
═══════════════════════════════════════════════════════════
🛡️ ImmuneEval+ Results
═══════════════════════════════════════════════════════════

Batch │ Cases   │ TP │ FP │ FN │ TN │ Recall │ Precision │  F1  │ AB
──────┼─────────┼────┼────┼────┼────┼────────┼───────────┼──────┼──────
  1   │  1-10   │  X │  X │  X │  X │   XX%  │    XX%    │ XX%  │ 0→X
  2   │ 11-20   │  X │  X │  X │  X │   XX%  │    XX%    │ XX%  │ X→X
  3   │ 21-30   │  X │  X │  X │  X │   XX%  │    XX%    │ XX%  │ X→X
  4   │ 31-40   │  X │  X │  X │  X │   XX%  │    XX%    │ XX%  │ X→X
──────┼─────────┼────┼────┼────┼────┼────────┼───────────┼──────┼──────
TOTAL │  1-40   │  X │  X │  X │  X │   XX%  │    XX%    │ XX%  │ 0→X
═══════════════════════════════════════════════════════════

Learning Progression:
  Batch 1 → 2: {delta F1}% improvement
  Batch 2 → 3: {delta F1}% improvement
  Batch 3 → 4: {delta F1}% improvement
  Average learning rate: {avg delta}% F1/batch

Antibodies learned: {total} new patterns discovered

Domain Breakdown:
  fitness: {recall}% recall ({tp}/{total_issues})
  code:    {recall}% recall ({tp}/{total_issues})
  writing: {recall}% recall ({tp}/{total_issues})

═══════════════════════════════════════════════════════════
```

### Phase 3 — Save & Restore

1. Save the full results to `~/.claude/skills/immune/eval/results/{YYYY-MM-DD}.json`:
```json
{
  "date": "YYYY-MM-DD",
  "version": "1.0",
  "batches": [
    {
      "batch": 1,
      "ab_before": 0,
      "ab_after": N,
      "cases": [
        {"id": "IE-001", "result": "pass|fail", "tp": N, "fp": N, "fn": N, "tn": N}
      ],
      "recall": 0.XX,
      "precision": 0.XX,
      "f1": 0.XX
    }
  ],
  "totals": {
    "tp": N, "fp": N, "fn": N, "tn": N,
    "recall": 0.XX, "precision": 0.XX, "f1": 0.XX,
    "antibodies_learned": N,
    "learning_rate_avg": 0.XX
  }
}
```

2. **CRITICAL: Restore BOTH original memories.** Write back the backup content that was saved in Phase 0:
   - `~/.claude/skills/immune/immune_memory.json` ← original antibodies
   - `~/.claude/skills/immune/cheatsheet_memory.json` ← original strategies
   The benchmark must NOT permanently alter the production memories.

Log: `[EVAL] Memory restored to original state ({N} antibodies + {M} strategies)`

## Error Handling

- If an agent returns invalid JSON: score that case as all-FN (worst case) and continue
- If an agent times out: skip and score as all-FN
- If the dataset file is missing: abort with error message
- Always restore BOTH memories (immune + cheatsheet), even if the benchmark fails midway
