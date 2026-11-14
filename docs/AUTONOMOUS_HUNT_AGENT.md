# Autonomous Hunt Agent 1.0

The `agent` CLI runs a persistent mission for one configured target. It chooses
from the actual available actions, executes existing Recon/Analysis/case engines,
observes their results and continues until work is exhausted, stopped, or bounded
by the mission limits. Mission state, actions and results survive process exits.
The application/core schema stays at 8.8.19/18; the agent has its own additive
`hunt_missions` and `hunt_steps` tables, installed on first use.

## Choose a planner

AI mode is the default. It uses the OpenAI-compatible Chat Completions endpoint
and JSON response mode. Configure a model that supports these interfaces.
No provider key is bundled or stored in mission records.

OpenAI:

```bash
export HUNT_AI_MODEL=gpt-4.1-mini
export HUNT_AI_BASE_URL=https://api.openai.com/v1
./recon-monitor.sh secrets set hunt-ai-api-key
```

The existing secrets command prompts for the key and stores it in macOS Keychain.
Linux/non-Keychain installations can supply `HUNT_AI_API_KEY` in their process
environment or secret manager. Do not commit keys or paste them into reports.

A local Ollama model with OpenAI-compatible JSON mode:

```bash
export HUNT_AI_MODEL=qwen2.5:14b
export HUNT_AI_BASE_URL=http://127.0.0.1:11434/v1
```

The local model must already be installed and its server running. Remote
providers require HTTPS; HTTP is accepted only for literal loopback/localhost
providers. API redirects are refused. Provider errors or invalid decisions pause
the mission; there is no silent fallback to a different planner or action.

`--planner rules` explicitly selects deterministic priority ordering. It requires
no model and is useful for offline acceptance and installations without AI.

## Start and control missions

```bash
# Network collection followed by automatic research, within the target policy.
./recon-monitor.sh agent run --target example.com --max-steps 24 --max-cases 6 --max-runtime 1800

# Research already stored evidence without new target traffic.
./recon-monitor.sh agent run --target example.com --run RUN_ID --offline

# Fully local research without a provider connection.
./recon-monitor.sh agent run --target example.com --offline --planner rules

./recon-monitor.sh agent list
./recon-monitor.sh agent status --mission HUNT-ID
./recon-monitor.sh agent stop --mission HUNT-ID
./recon-monitor.sh agent resume --mission HUNT-ID
./recon-monitor.sh agent report --mission HUNT-ID
```

Replace the example target with its **exact configured target name**. A supplied
Run must belong to that target and must not currently be running. Offline mode
without `--run` selects the target's latest stored non-running Run. AI-based
offline mode still contacts the configured model provider; `rules` mode does not.

Network missions require the installation's authorization setting. Recon reuses
the normal CLI with active modules disabled at the CLI gate. The target policy's
scope, transport restrictions, request/byte budgets and pipeline behavior still
apply. Resumed collection reuses the same Run ID and its stored budgets. A changed
policy invalidates the mission; create a new mission to adopt changed scope.

Each mission is single-target and only one agent may run for a target at a time.
`stop` is checked during collection, after AI decisions and between engine calls.
An in-progress offline engine/approved validation completes its bounded call
before the stop is observed. Collection subprocess groups are terminated on
stop/deadline. Mission lifetime includes time between resumes and is not reset.
Offline engine deadlines are cooperative between calls. Exhausted missions are
terminal; starting another mission creates a separate research budget.

## Research flow and results

1. Collect through the existing Recon pipeline, or adopt the selected stored Run.
2. Run the existing immutable-input Analysis engine for the exact target/Run.
3. Rank available Investigation Queue clusters and link their existing cases.
4. Perform candidate-scoped offline provenance validation.
5. Optionally execute **already approved** passive-live plans with `--allow-live`.
6. Produce evidence-linked case drafts and a mission report.

The planner sees only offered action IDs, tool names, family/category metadata,
numeric priorities/coverage and bounded result summaries. Target response bodies,
headers, cookies, arbitrary case prose and URLs are not sent to it. A model cannot
invent shell commands, URLs, tools, target names, scope changes or approvals.
Its selected ID is checked against the current offered actions before dispatch.
Configuration/policy and stop controls are rechecked after each AI decision.

The agent does not approve its own validation plans. `--allow-live` permits only
existing approved passive-live plans for cases in the same mission/target.
Global/target active gates and all Safe Validation checks remain enforced.
`--max-live-requests` defaults to 24. Each plan's entire bounded request count is
reserved durably before dispatch and retained on failure/interruption. A live
step interrupted by process exit is marked uncertain and never automatically
replayed. Controlled/manual families retain their existing execution boundaries.

Reports are saved with private file permissions under:

```text
output/hunt-agent/HUNT-ID/mission.json
output/hunt-agent/HUNT-ID/mission.md
output/hunt-agent/HUNT-ID/collection.log
```

Successful orchestration is distinct from complete collection or confirmed
vulnerabilities. Partial collection and failed/uncertain actions produce
`completed_with_gaps`; step/lifetime exhaustion produces `budget_exhausted`.
The existing case engine owns confirmation and evidence claims. Reports retain
missing evidence and uncertainty, and platform submission is not automated.
CLI execution exits 0 for completed missions and 2 for paused/gapped/exhausted
missions; status/list/report commands remain normal read operations.

## Verification

```bash
python -m unittest discover -s tests -p 'test_hunt_agent.py' -v
```

Regressions exercise actual offline Analysis and case/validation/report engines,
cross-target source rejection, policy changes, concurrent execution, persistent
limits, stop during planning, crash recovery, invalid model actions and provider
data minimization. Tests use synthetic fixtures and do not scan external targets.
Native provider quality requires a configured local/cloud model; mocked provider
protocol tests do not establish live model accuracy or successful bounty reports.
