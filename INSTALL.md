# Installation

## Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI installed and configured

## Quick Install

1. **Copy the skill files** to your Claude Code config directory:

```bash
# Immune skill + memory files
cp -r skill/ ~/.claude/skills/immune/

# Scanner agent
cp skill/agents/immune-scan.md ~/.claude/agents/immune-scan.md

# Eval skill (optional)
mkdir -p ~/.claude/skills/immune-eval/
cp skill/eval/skill.md ~/.claude/skills/immune-eval/skill.md
cp skill/eval/dataset.json ~/.claude/skills/immune/eval/dataset.json
```

2. **Verify installation** — in Claude Code, type `/immune` and it should load the skill.

## File Locations

After installation, your structure should be:

```
~/.claude/
  skills/
    immune/
      skill.md              # Main orchestrator
      config.yaml           # Configuration (editable)
      immune_memory.json    # Antibodies (auto-managed)
      cheatsheet_memory.json # Strategies (auto-managed)
      eval/
        dataset.json        # ImmuneEval+ test cases
        skill.md            # Eval runner
  agents/
    immune-scan.md          # Haiku scanner agent
```

## Chimera Integration (optional)

If you also use the [Chimera](https://github.com/contactjccoaching-wq/chimera) pipeline, the immune system integrates automatically as Phase 3. Both skills share the same memory files.
