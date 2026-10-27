# Claude Code skills

Copied from [obra/superpowers](https://github.com/obra/superpowers) at commit `2ce8aa1` (MIT, see `LICENSE.superpowers`).

| Skill | Kicks in when |
|---|---|
| `systematic-debugging` | a bug, failing test or build error shows up — root cause before any fix |
| `test-driven-development` | implementing a feature or bugfix — failing test first |
| `verification-before-completion` | about to claim something works — run the check and show the output first |
| `requesting-code-review` | a feature is done — hands the diff to a fresh reviewer subagent |
| `receiving-code-review` | review feedback arrives — verify each point before applying it |

Claude picks these up automatically from their descriptions; you can also call one by name, e.g. `/systematic-debugging`.
