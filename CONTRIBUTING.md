# Contributing

Thanks for helping build Hyblis.

## Workflow

1. Open an issue first for anything larger than a small fix, so the approach can be agreed.
2. Branch from `main`: `feat/<topic>`, `fix/<topic>` or `docs/<topic>`.
3. Keep each pull request to one change, with tests. The PR template lists what reviewers look for.
4. CI must pass (`scripts/ci_tests.sh`). For runner changes also run `scripts/run_tests.sh` locally: it adds the
   Foundry and toy-chain suites, which need Foundry 1.9.0.

## Rules that are not negotiable

- **Verdicts come only from the execution trace.** Never let a proof's own output (logs, asserts, events) decide
  a verdict.
- **Scoring stays deterministic.** No I/O, randomness or local clocks in `scoring/hyblis_scoring`.
- **No secrets in the repository.** Keys, tokens and wallet files never get committed.
- **Private stays private.** Report contents, bounty amounts and unreleased programs never reach a public surface;
  the end-to-end tests check this.

## Commit messages

Short imperative subject (`runner: reject dangling prank at step boundary`), then a body that says why.
