# Project skills

Skills in this folder are loaded by Claude Code for this repository. They
are plain Markdown instructions: no scripts, no downloads, no network use.
None of them is copied to pfSense (install.sh only copies from `src/`).

| Skill | Source | What it is for |
|-------|--------|----------------|
| [dead-code-removal](dead-code-removal/SKILL.md) | [ArabelaTso/Skills-4-SE](https://github.com/ArabelaTso/Skills-4-SE/tree/4f38503747e0617504bce5329283ef837d375c09/skills/dead-code-removal) at commit `4f38503`, Apache-2.0 (LICENSE copied alongside), unmodified | Finding and removing unused code: scan, verify every reference before removing, one atomic commit per removal. |

## Notes for this repository

- **dead-code-removal**: its scanner commands (`npx tsc`, `vulture`,
  `staticcheck`) are for other languages and do not apply here; this is
  PHP, so references are verified with `grep` across `src/`, `tests/` and
  the pfSense core files the hooks patch. Functions named in `hook.inc`
  (`webauthn_gate`, `webauthn_cached_privileges_allowed`,
  `webauthn_xmlrpc_guard`), in `system_webauthn.php` or in
  `webauthn.js` called from PHP-rendered pages (`webauthnLoginInit`,
  `webauthnRegisterInit`) are entry points and are never "dead".
- On this security code, a removal only lands after `php -l`, `sh -n`
  and the full `tests/` suite pass (`php tests/run.php`), and the user's
  instructions take precedence over the skill's (for example: show the
  list and wait for approval before removing anything).
