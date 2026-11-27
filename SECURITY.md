# Security policy

Hyblis verifies other people's exploits, so we take reports about Hyblis itself seriously.

## Reporting a vulnerability in Hyblis

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

Useful to include: what is affected (runner, gateway, scoring, validator, site, vault contract), how to reproduce
it, and the impact you expect. We aim to acknowledge reports within 3 working days.

## Scope

- The runner and its sandbox (`runner/`): anything that lets a proof affect its own verdict, another job, or the
  host.
- The gateway and pipeline (`platform/`): signature checks, intake, dedup, private data exposure.
- Scoring and weights (`scoring/`, `validator/`): anything that makes validators disagree or pays the wrong hotkey.
- The vault contract (`chain/vault/`).

Vulnerabilities in the programs listed on Hyblis are not reported here: submit them through Hyblis itself, or
through the program's own bug bounty.
