## Agent skills

### Issue tracker

Issues live in GitHub Issues; use the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage labels use their default names. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: root `CONTEXT.md` and `docs/adr/`. See `docs/agents/domain.md`.

### Structural code search

You are operating in an environment where `ast-grep` is installed.
For any code search that requires understanding of syntax or code structure, you should default to using `ast-grep --lang [language] -p '`
