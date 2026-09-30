# Contributing to Brainy

Thanks for your interest! A few ground rules keep Brainy safe and maintainable.

## Before you start

- For anything larger than a small fix, open an issue first and describe the idea.
- All contributions require agreeing to the [CLA](CLA.md) (one line in your first PR).

## Principles

- **Standard library only.** The core has zero third-party dependencies — please keep it that way.
- **Fail closed.** New capabilities are off by default and require explicit configuration.
- **No generic execution over MCP.** No shell, filesystem or eval tools. Every tool is a narrow,
  ACL-checked, audited function.
- **No secrets** in code, tests, logs, audit events or the knowledge base.

## Development

```bash
for t in tests/test_*.py; do python3 "$t" || exit 1; done
```

Tests use temporary databases and knowledge repositories; they never touch a real installation.
Every PR must keep all tests green and add tests for new behaviour.

## Pull requests

- One topic per PR, with a clear description of *why*.
- Update docs (`README.md`, `docs/`) when behaviour or configuration changes.
