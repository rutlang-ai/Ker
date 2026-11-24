# Repository guidance

## Ker scope and architecture

Ker provides exported APIs, DPDK integration, and the compatibility/runtime
adapters required to compile and run original Linux kernel networking code in
userspace. Application business logic belongs to callers.

Protocol behavior must come from the original Linux implementations. Do not
implement or extend Ker-owned substitutes for TCP/UDP state machines, handshake,
ACK/window processing, retransmission, congestion control, or connection teardown.
Ker-owned code may translate APIs and adapt memory, packet ownership, devices,
time, scheduling, synchronization, and other required runtime facilities while
preserving upstream semantics.

When a kernel dependency is missing, implement its adapter or make the unsupported
boundary explicit; do not bypass it with a simplified protocol implementation.
Existing custom protocol paths are architectural deviations to assess and
replace, not templates for further feature milestones. Interoperability tests
must distinguish imported-kernel behavior from Ker-owned protocol behavior.

## Pull request language

Use English for all future pull request titles, descriptions, and agent-authored
review replies or PR conversation comments. Preserve technical identifiers and
source links. This is the user's explicit preference; conversation and repository
documentation may continue in Chinese unless requested otherwise.

## Preserve upstream code through adapters

Prefer Ker compatibility headers, wrappers, and runtime adapters over modifying
upstream Linux code. Keep Linux source and imported upstream code unchanged
wherever possible so the pinned Linux dependency can be updated without carrying
local patches or creating avoidable merge conflicts. Apply the same approach to
other upstream dependencies, including DPDK.

Implement userspace behavior and integration changes in Ker's adaptation layer.
Preserve upstream structures, interfaces, and semantics when exposing them through
that layer. Do not silently replace unsupported behavior with a successful stub;
make unsupported boundaries explicit. If an upstream modification is unavoidable,
document why adaptation cannot solve it and keep the change minimal and isolated.
This policy does not prohibit changes to Ker-owned implementation code.

## Repository skills

- `pr-watchdog`: [.agents/skills/pr-watchdog/SKILL.md](.agents/skills/pr-watchdog/SKILL.md).
  Read and use this skill when asked to monitor or shepherd GitHub PRs, including
  review feedback, CI failures and rebase conflicts. Importing the skill alone
  does not start a watch. Never merge without an explicit user request.

The skill and its scripts were copied from the local
`clapdb.com/clapdb/.agents/skills/pr-watchdog` directory, whose checkout was at
`33d180d2d85473801b94eadf9b8073e83a95c4f9`. Ker adds a lifecycle launcher, propagates polling errors to the coordinator,
and adapts the skill to available worker models. Run its tests from the Ker repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .agents/skills/pr-watchdog/scripts -p 'test_*.py'
```

The skill requires Python 3, authenticated `gh`, and a persistent coordinator
session for continuous event dispatch. The installed Codex CLI supports the
`codex queue --thread ... --message ...` interface used by the dispatch script.
Keep polling state and the review-request outbox outside all worktrees.
