# Contributing to blue-kakapo

Thanks for helping build an open, trustworthy SOC. This project values **substance over theatre**:
honest claims, tested code, and guardrails that actually hold.

## Development setup

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/dibakshya01/blue-kakapo.git
cd blue-kakapo               # tip: a path WITHOUT spaces avoids a uv editable-install quirk
uv sync --extra dev --extra otel
uv run pytest               # tests
uv run ruff check src tests # lint
uv run ruff format src tests
uv run mypy                 # types
```

All four must pass before a PR merges (CI enforces it on Python 3.11 and 3.12).

## Ground rules

- **Spec-first.** Behavior changes start in [`build-plan.md`](build-plan.md), then the code. New
  functional requirements get a testable `FR-` entry.
- **Test every claim.** Bug fixes and security fixes ship with a test that fails before and passes
  after. Security controls get an adversarial test (injection, excessive-agency, etc.).
- **No unaudited metrics.** Don't add accuracy/efficacy numbers to docs; extend the eval harness
  instead.
- **Least privilege & human-in-the-loop.** Any new state-changing action must route through the
  Guardian and declare reversibility. Treat all tool/alert content as untrusted data.
- **Keep dependencies few and justified.** New runtime deps need a one-line rationale in the PR.

## Agents, connectors, policies

- New **agents** implement the Agent SDK contract (`build-plan.md` §4.6) and ship an AgBOM + the
  per-agent "deeply implemented" acceptance tests.
- New **connectors** implement the Connector SDK, declare capabilities + action reversibility, and
  ship contract tests (mock + real where feasible).

## Commit / PR

- Small, focused PRs with a clear description of *what* and *why*.
- Reference the `FR-`/stage you're addressing.
- Be kind and specific in review. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
