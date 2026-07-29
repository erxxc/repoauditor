# repoauditor

`repoauditor` reviews an unfamiliar codebase for security risks. It creates a read-only
snapshot, maps the application, combines AI-assisted review with established security
scanners, challenges likely false positives, pauses for human decisions when evidence is
uncertain, and produces two reports:

- an engineering backlog with concrete remediation work; and
- a leadership memo summarizing risk in business terms.

You do not need a security background to run it. Findings are leads to review, not proof
that a system has been compromised. See [`repoauditor-scaffold.md`](repoauditor-scaffold.md)
for the design and [`CLAUDE.md`](CLAUDE.md) for the project’s architectural rules.

The owner-confirmed POC acceptance boundary is
[`docs/poc-definition-of-done.md`](docs/poc-definition-of-done.md). Current MVP work is
limited to [`docs/poc-recovery-plan.md`](docs/poc-recovery-plan.md); tuning and future
extensions are governed separately in
[`docs/optimizations/optimization-register.md`](docs/optimizations/optimization-register.md).

## Choose the menu or commands

For a guided, numbered interface, run this in an interactive terminal:

```sh
uv run repoauditor
```

The menu shows pending review counts and offers the demo, repository scans, review,
finalization, history, and installation checks. It prints the equivalent command before
running an action, so the same workflow can later be automated. You can also open it
explicitly with `uv run repoauditor menu`.

```text
┌───────────────────────────────────────────────┐
│ RepoAuditor                                   │
├───────────────────────────────────────────────┤
│ 1. Run guided demo                            │
│ 2. Scan a repository                          │
│ 3. Review pending findings (2 pending)        │
│ 4. Finalize reports                           │
│ 5. View repositories and run history (1)      │
│ 6. Check installation                         │
│ 7. Exit                                       │
└───────────────────────────────────────────────┘
Select an option [1]:
```

The counts come from the local audit store. The menu will not run finalization while the
selected repository still has unresolved review requests; it points the user back to the
review option instead. Installation checks ask separately before making a live, potentially
billable model request.

Existing commands remain unchanged. Scripts, redirected input, and other non-interactive
sessions receive normal command help rather than being blocked by a prompt.

## Fastest macOS setup

The commands below assume you have [Homebrew](https://brew.sh/) and are in a terminal.
If `brew --version` fails, install Homebrew first by following its official instructions.

1. Install the required command-line tools:

   ```sh
   brew install python@3.12 uv git
   ```

2. Install the recommended security scanners:

   ```sh
   brew install semgrep gitleaks pip-audit osv-scanner
   ```

   These scanners are optional, but installing all four gives the broadest coverage.
   `repoauditor` still runs when one is absent and clearly reports the missing coverage.

3. Download the project and enter its directory. If you already have this checkout,
   just `cd` into it instead:

   ```sh
   git clone https://github.com/erxxc/repoauditor.git
   cd repoauditor
   ```

4. Install its Python dependencies:

   ```sh
   uv python install 3.12
   uv sync --python 3.12
   ```

   Do not install the Python packages from `pyproject.toml` one by one. `uv sync` creates
   the project environment and installs the tested dependency set for you.

5. Configure a model and API key as described in [Choose a model provider](#choose-a-model-provider),
   then verify the installation:

   ```sh
   uv run repoauditor doctor
   ```

6. Optionally make one live model request to verify the endpoint, credentials, selected
   model, and structured-output support:

   ```sh
   uv run repoauditor doctor --check-model
   ```

   This check may incur a small provider charge. Plain `doctor` never calls the model.

The Homebrew package names above match the current formulae for
[Python 3.12](https://formulae.brew.sh/formula/python@3.12),
[uv](https://formulae.brew.sh/formula/uv), [Git](https://formulae.brew.sh/formula/git),
[Semgrep](https://formulae.brew.sh/formula/semgrep),
[Gitleaks](https://formulae.brew.sh/formula/gitleaks),
[pip-audit](https://formulae.brew.sh/formula/pip-audit), and
[OSV-Scanner](https://formulae.brew.sh/formula/osv-scanner).

## Run the guided demo

The repository includes a small, intentionally vulnerable storefront designed for a safe,
repeatable demonstration. It is analyzed statically and is never started as a web service.
After completing the setup above, provide the Anthropic key in the current terminal and run:

```sh
export ANTHROPIC_API_KEY="your-key-here"
./demo
```

The launcher uses `uv` to synchronize the project environment, verifies dependencies,
scanners, SQLite, credentials, and the configured model, then runs the complete pipeline.
If a finding needs judgment, it explains the evidence and asks the operator to choose
`confirm` or `dismiss` and enter a short rationale. The default choice for the deliberately
ambiguous demo case is `dismiss`; the decision remains human and auditable.

At completion it writes both reports, a quantitative appendix, and Markdown/JSON UAT
scorecards comparing the stored evidence with the ten-case fixture matrix. A partial score
still produces artifacts so misses can be reviewed instead of being hidden by an early exit.
The model check and scan make live API requests and may incur provider charges.

If no key is present, the demo stops before scanning and prints the exact environment-variable
command needed. It never writes the key to configuration, SQLite, reports, or the repository.
Advanced automation may use `./demo --non-interactive`; that mode stops successfully at an
open review request instead of making a decision for the user.

If the bounded falsification budget pauses the demo, continue exactly as printed:

```sh
uv run repoauditor resume uat_lightweight_app
uv run repoauditor demo --continue
```

Repeat `resume` only while it reports deferred findings. `demo --continue` never repeats
ingest, map, or detect; it completes the review checkpoint, both reports, the quantitative
appendix, and the scorecards.

The scorecard distinguishes the final security outcome from test-instrument coverage. A
negative control passes when it never becomes a countable finding, whether it was detected
and killed or never raised. Candidate creation, falsification exercise, and expected-source
coverage remain visible separately so a safe non-finding is not misreported as a security
failure.

## Linux or an existing development environment

You need Git and `uv`; `uv` can install the correct Python version itself. Install Git
with your operating system’s package manager and install `uv` using the
[official uv installation instructions](https://docs.astral.sh/uv/getting-started/installation/).
Then run:

```sh
uv python install 3.12
uv sync --python 3.12
uv run repoauditor doctor
```

Install Semgrep, Gitleaks, pip-audit, and OSV-Scanner using their official installation
instructions if they are not available from your system package manager. You can also
leave deterministic scanning disabled by setting `run_deterministic_tools = false` in
the `[detect]` section of `config.toml`; this reduces coverage and runs only the model
lenses.

## What gets installed

Required:

- **Python 3.12** runs the application.
- **uv** creates the isolated environment and installs all Python dependencies.
- **Git** is needed for Git repositories and remote Git URLs. A plain local directory
  can still be snapshotted without Git.
- **A supported model endpoint and credential** are needed for mapping, AI detection,
  falsification, and normalization.

Recommended security scanners:

- **Semgrep** checks source code against static-analysis rules.
- **Gitleaks** looks for accidentally committed credentials; detected secret values are
  redacted before findings are persisted.
- **pip-audit** checks Python dependency manifests for known vulnerabilities.
- **OSV-Scanner** checks supported dependency manifests across multiple ecosystems.

If OSV-Scanner's recursive mode cannot discover a bare `requirements*.txt`, RepoAuditor
retries a bounded set of those files explicitly. That recovery is reported as **partial**
coverage because other manifest types may still be undiscovered; it is never presented as a
complete recursive scan.

SQLite does not need a separate installation. `doctor` and `run` automatically create
or upgrade `data/repoauditor.db`. All generated data is stored under the configured
`data/` directory, which is ignored by Git.

## Choose a model provider

Model-backed stages send selected source-code context to the configured endpoint. Only
scan code you are authorized to review and permitted to share with that provider. A local
OpenAI-compatible endpoint can be used when source code must remain on your machine.

### Anthropic, the default

Leave the default `[llm]` provider in `config.toml`, select a model available to your
account under `[model]`, and set your key in the current terminal:

```sh
export ANTHROPIC_API_KEY="your-key-here"
uv run repoauditor doctor
```

Environment variables apply only to the current shell unless added to your shell’s secure
configuration. Never commit API keys to `config.toml` or the repository.

### OpenAI-compatible endpoint

Edit `config.toml`:

```toml
[model]
name = "your-model-name"

[llm]
provider = "openai-compatible"
base_url = "http://localhost:11434/v1"
api_key_env = "OPENAI_API_KEY"
response_format = "json_schema"
```

Then set the environment variable named by `api_key_env`:

```sh
export OPENAI_API_KEY="your-key-here"
uv run repoauditor doctor --check-model
```

The base URL must be the API root; `repoauditor` appends `/chat/completions`. Set
`api_key_env = ""` only for an intentionally keyless local endpoint. If the server does
not implement JSON Schema response formats, try `response_format = "json_object"`, then
`"none"`. Pydantic validation and bounded retries remain active in all three modes.

## First scan: step by step

Run commands from the `repoauditor` project directory.

### 1. Check the setup

```sh
uv run repoauditor doctor
```

`doctor` checks Python packages, the model credential, Git, scanner executables, and the
SQLite schema. Resolve any line marked `error` before scanning. Scanner warnings mean the
scan can continue with reduced coverage.

### 2. Start the scan

For a local repository or directory:

```sh
uv run repoauditor run /path/to/project
```

For a Git URL:

```sh
uv run repoauditor run https://github.com/owner/project.git
```

This is a foreground process and may take a long time on a large repository. Keep the
terminal open, or run it under `tmux`, `screen`, or another process supervisor. Each stage
prints start/end times, elapsed time, counts, and important artifact paths. The stages are:

1. **ingest** — creates an immutable snapshot and assigns a repository ID;
2. **map** — identifies entry points, data stores, integrations, and trust boundaries,
   then writes a plain-text architecture schematic;
3. **detect** — runs model lenses and available deterministic scanners;
4. **triage** — ranks likely actionable findings and suppresses weak signals;
5. **falsify** — tries to disprove each candidate;
6. **normalize** — reconciles evidence and routes uncertainty to review.

The run intentionally stops after normalization. It never silently skips the review
checkpoint and proceeds to final reports.

### Read the architecture map

The map stage writes a terminal-friendly artifact at:

```text
data/artifacts/<repo-id>/architecture-<commit>.txt
```

Its path appears in the map completion line and the final run recap. You can regenerate it
for an ingested repository with:

```sh
uv run repoauditor map <repo-id>
```

The schematic draws only relationships carried by the recovered map: entry points crossing
named trust boundaries and the recorded direction of external integrations. Data stores are
listed as an inventory because the current schema does not establish component-to-store
flow edges. A missing node or edge means “not recovered,” not proof that it does not exist.
This makes the file useful as an initial architecture-review aid without presenting inferred
data flows as observed facts.

## How the decision engine works

`repoauditor` treats scanner and model output as candidate evidence, not as an automatic
verdict. The decision path is deliberately staged:

1. **Detection gathers attributed signals.** Model lenses and deterministic scanners
   contribute findings with source attribution and code citations. Multiple reports of the
   same issue are retained as agreement evidence rather than counted as separate risks.
   Shared-model lenses are explicitly treated as correlated multi-lens agreement; only
   different evidence mechanisms or distinct deterministic tools count as independent
   corroboration.
   Model citations must resolve exactly to repository source before persistence: a unique
   location corrects a misattributed file/range, while absent or ambiguous citations are
   logged and rejected rather than becoming malformed findings.
   Repository-controlled text is delimited as untrusted evidence at detect and falsify
   model boundaries; comments or docstrings that resemble instructions cannot replace the
   stage policy or output contract.
2. **Triage ranks actionability.** The classifier estimates `P(actionable)` and records its
   feature attribution. This probability represents uncertainty that a finding is real and
   useful—not technical severity and not an expected incident frequency.
3. **Falsification challenges the candidate.** A bounded evidence loop checks reachability,
   attacker control, and mitigating controls. It confirms, kills, defers, or leaves the
   candidate unresolved; it never silently drops an inconclusive result.
   For Python SQL injection, command injection, and SSRF candidates, a deterministic local
   def-use slice adds source/assignment/sink and possible-control evidence. The slice is
   explicitly non-authoritative: it does not prove reachability, path feasibility, attacker
   control, or sanitizer effectiveness, and unsupported/dynamic flows are marked incomplete.
   Supported slices also produce an idempotent structured `SecurityClaim` plus a
   `ClaimVerification` audit record. The independently versioned checker reopens the pinned
   snapshot and reconstructs the supported local AST/def-use facts without consuming the
   slicer's in-memory evidence. A `structurally_verified` claim means only that exact source,
   assignment-chain, and sink facts closed under that checker; it is not empirical validation
   of exploitability, end-to-end reachability, control effectiveness, or risk.
4. **Normalization reconciles evidence.** Findings that refer to the same underlying issue
   are grouped, source disagreements are adjudicated, and unresolved cases become review
   requests.
5. **Human review is a hard gate.** Undecided requests block final analysis. Decisions and
   later corrections are append-only and require a rationale, preserving the audit trail.
6. **Analysis keeps technical and financial decisions separate.** Deal-risk weighting helps
   prioritize diligence and remediation without overwriting technical severity. Separately,
   FAIR-style Monte Carlo analysis reports a loss range and exceedance curve rather than a
   single confidently precise number.

### Interpreting triage accuracy

Until the store contains at least 40 real scored labels, triage validation measures the
synthetic training generator—not real-world classifier performance. Treat `P(actionable)` as
queue-prioritization guidance during this cold-start period. The CLI prints the active basis:
`synthetic_row_random`, provisional `real_row_random`, or `engagement_grouped`.

Inspect observed threshold tradeoffs without asking the tool to choose a threshold:

```sh
uv run repoauditor triage-stats             # all engagements
uv run repoauditor triage-stats <repo-id>   # one engagement
uv run repoauditor triage-stats --label-source derived  # automation-derived cohort
uv run repoauditor triage-stats --run-id <triage-run-id> # one compatible score cohort
uv run repoauditor triage-collection        # label gate, dual verdict views, review QA
uv run repoauditor quant-audit <repo-id>    # read-only prior/double-counting audit
```

Below 40 real scored labels, this command deliberately withholds the curve. Engagement-
grouped validation additionally requires at least eight distinct evaluation families.
An evaluation family defaults to one stable repository identity. Configure
`[triage.evaluation_family_overrides]` when clones, renamed repositories, or separate
pre/post ids must remain on the same side of the holdout; this mapping affects evaluation
only, never classifier features or predictions. A small,
deterministic sample of suppressed-but-falsification-confirmed findings is routed to review
on orchestrated runs so labels are not collected exclusively from high-ranked findings.
The default statistics cohort uses manual and human-review labels; falsification-derived
labels remain separately selectable for training-data diagnostics. Each scoring pass records
its model/package version, feature-schema hash, training mix, validation basis, available
scanner versions, and timestamp, and immutable score history supports run-specific comparison.

For controlled UAT collection, every direct analyst assessment requires a rationale. Use an
explicit abstention when the available evidence cannot support a binary decision:

```sh
uv run repoauditor triage-label <finding-id> \
  --disposition uncertain \
  --rationale "Runtime tenant context is unavailable" \
  --dimension tenant-isolation \
  --dimension authorization
```

Detailed dispositions distinguish tool error, unreachable paths, absent attacker control,
effective mitigations, duplicates, and technically valid-but-non-actionable issues; see the
[adjudication taxonomy and evaluation protocol](docs/adjudication-taxonomy.md).
`insufficient_evidence` (and legacy `uncertain`) assessments are retained in an append-only
audit history but never enter model training. Decided outcomes update the effective manual
binary label only when the finding has a compatible triage feature row. LLM, secrets, and
SCA findings without that row can still be assessed, but are clearly recorded as
assessment-only evidence and excluded from the classifier gate/training. For a material
case, add `--material`: the assessment remains withheld until
a second distinct analyst records the same detailed disposition. Materiality is explicit,
never inferred from severity, and disagreement remains visible rather than becoming a
training label. Repeat `--dimension` with analyst-verified coverage descriptors such as
`business-logic`, `authorization`, `tenant-isolation`, `multi-service`, `ci-iac`,
`agent-tool-boundary`, `dependency`, `secret`, `dead-code`, `safe-control`, or `near-miss`.
These values are declared, not guessed from a scanner rule name. The controlled activation
floor remains 40 usable human/manual-or-review binary labels across eight distinct source
repositories; automation-derived falsification labels do not advance that gate. The preferred
maturity target is 100–200 labels with both classes represented.

The quantitative model separates four concepts that should not be collapsed into one score:

- **Finding validity:** a Bernoulli gate informed by triage, falsification, and human review.
- **Threat-event frequency:** a sourced conditional industry baseline, scaled by production
  exposure derived from the application map.
- **Vulnerability/control strength:** the chance an exposed threat event becomes a loss
  event. Confirmed unmitigated findings receive no invented control credit; an analyst may
  supply known compensating controls through configuration.
- **Loss magnitude:** a sourced distribution adjusted by an explicit engagement loss-scale
  override. Revenue band is recorded, but defaults to neutral `1.0×` scaling until an exact,
  verified band-to-loss curve is available.

EPSS and CISA KEV are used only when a finding maps to a real CVE and real enrichment data is
available. Severity labels are never renamed or converted into EPSS/KEV signals. Findings
without CVE enrichment use the cited industry frequency baseline and are labeled as such.
Every published prior and engagement input retains provenance so a reviewer can distinguish
published data, derived application evidence, conservative defaults, and analyst overrides.

RepoAuditor also runs a read-only integrity audit over resolved scenario inputs. If it finds
a blocking applicability problem—currently including reuse of a full organization-level
frequency baseline once per finding—the CLI, leadership memo, and quantitative appendix
visibly label the dollar output **experimental and not decision-grade**. The figures remain
available for method evaluation, but must not be used for deal, budget, or risk-acceptance
decisions. Inspect the attributable evidence with:

```sh
uv run repoauditor quant-audit <repo-id>
```

Analyst overrides live in `[risk_quant]` in `config.toml`. Keys may name one scenario, such
as `data_breach`, or use `"*"` for an engagement-wide value. Recognized scenario names are
`credential_compromise`, `data_breach`, `rce_full_compromise`, `service_disruption`, and
`uncategorized`; a misspelled name fails configuration loading instead of being ignored:

```toml
[risk_quant]
company_revenue_band = "10m_to_100m"
control_strength_overrides = { "data_breach" = 0.70 }
exposure_overrides = { "*" = 0.80 }
loss_scale_overrides = { "data_breach" = 1.25 }
```

Control and exposure values must be between `0` and `1`; loss-scale values must be positive.
Overrides are visibly labeled in the risk appendix and, when `--record-audit` is used,
stored alongside their provenance.

### 3. Resolve review requests

The run prints the assigned `<repo-id>`. If it reports open review requests, list them:

```sh
uv run repoauditor review list <repo-id>
```

For each request, decide whether the finding should be included:

```sh
uv run repoauditor review decide <repo-id> <request-id> \
  --decision=confirm \
  --rationale="Verified that untrusted input reaches this operation"
```

Or dismiss it with an auditable explanation:

```sh
uv run repoauditor review decide <repo-id> <request-id> \
  --decision=dismiss \
  --rationale="The cited path is unreachable in the deployed configuration"
```

If you are unsure, ask someone familiar with the application rather than guessing. The
rationale becomes part of the audit trail.

### 4. Produce both reports

After all review requests are decided:

```sh
uv run repoauditor finalize <repo-id>
```

`finalize` runs quantitative analysis and writes the engineering backlog and leadership
memo. It prints their file paths instead of flooding the terminal with Markdown. To also
print both complete reports:

```sh
uv run repoauditor finalize <repo-id> --print-reports
```

`finalize` refuses to run while review requests remain open and tells you which requests
are blocking it.

Add `--record-audit` when the quantitative result must be retained as an auditable run:

```sh
uv run repoauditor finalize <repo-id> --record-audit
```

Each audited rerun appends a `SimulationRun` and versions its scenario inputs against that
run. It does not overwrite an earlier quantitative record. Without `--record-audit`, reports
and appendix files are generated normally but no simulation/scenario snapshot is persisted.

## Common operating commands

```sh
# Show the latest ingested snapshot for each source repository.
uv run repoauditor repos list

# Show every ingested commit/snapshot.
uv run repoauditor repos list --all

# Inspect run history, stage timing/funnel summaries, or failure details.
uv run repoauditor runs list --repo-id <repo-id>
uv run repoauditor runs show <run-id>

# Resume an interrupted run automatically.
uv run repoauditor run <same-path-or-url>

# Continue a completed, safely bounded falsification batch without rerunning map/detect.
uv run repoauditor resume <repo-id>

# Ignore an incomplete prior run and start a separate run record.
uv run repoauditor run <path-or-url> --fresh
```

Map, detect, and normalize use idempotent writes, so a partially completed stage can be
rerun without duplicating its persisted records. Existing downstream finding verdicts are
preserved. Run history records stage status, timing, artifacts, attributable failures, and
the raw-to-review funnel: raw/unique candidates, duplicate amplification, triage suppression
context, falsification outcomes, normalization abstentions, and review-request counts.
Demo and direct stage runs use the same summaries: `runs show` retains the selected detection
regions, scanner execution status/failure detail, model/prompt provenance, and generated
artifacts without requiring a direct SQLite query.
Successful provider responses record authoritative input, output, cache, and latency
metadata per attempt. `repoauditor runs show <run-id>` reports the run totals. If a provider
failure does not expose usage metadata, the attempt is still counted and is explicitly
reported as `unknown-usage-calls`; repoauditor never invents a token value. Dollar cost
remains unavailable because no dated provider/model price table is persisted.

Two `[llm]` circuit breakers prevent any CLI-triggered provider operation from issuing
calls indefinitely:

```toml
max_calls_per_pipeline_run = 75
max_tokens_per_pipeline_run = 250000
```

The call ceiling includes failed attempts, even when the provider withholds token metadata.
The token ceiling uses only provider-reported input, output, and cache tokens and is checked
before each request, so one in-flight request can cross the threshold before the next call
is stopped. A budget stop is an attributable, resumable pipeline failure; review the stored
usage with `runs show`, raise a limit deliberately if justified, then rerun the same source.
Set a limit to `0` only when an external budget control is already in place.

Before falsification, repoauditor compares the pending queue with the active run's remaining
call capacity. It prints both the optimistic minimum (verdict plus self-critique) and the
conservative reservation covering every configured iteration and retry. Only the batch that
fits that reservation is attempted; the rest is recorded as deferred and remains resumable.
The independent token ceiling still applies before every request—future token consumption is
not guessed from prior calls. When a deferred backlog remains, `run` pauses before
normalize/review and points to `repoauditor resume <repo-id>`. Each resume invocation gets
a fresh, separately recorded budget while reusing the immutable snapshot and completed
map/detect/triage evidence. Continuation records are linked as one logical scan, and
`finalize` refuses to exclude unexamined work silently.

Direct `map`, `detect`, `falsify`, and `normalize` commands also create a durable run record,
fresh budget, and the same applicable stage summary used by `run`, as do
`doctor --check-model`, `falsify-convergence`, and
`qualify-instrument`. Expert and diagnostic entry points therefore cannot bypass the safety
boundary used by `run`, `resume`, and `demo`; inspect their usage and attributable failures
with `runs list` and `runs show`.
The opt-in `qualify-detection` command uses the same durable budget and reports its usage
inside structured output.

Dependency advisories also carry a canonical ecosystem/package/version/advisory identity.
This prevents unrelated CVEs from being merged merely because SCA scanners report them all
at manifest line 1, while allowing the same advisory returned by pip-audit and OSV-Scanner
to be treated as the same underlying issue.

Each provider request also uses `[llm].timeout_seconds` (120 seconds by default). Provider
SDK retries are disabled: repoauditor's shared reliability layer owns the bounded retry
count and persisted attempts. Validation, connection, timeout, HTTP 408, and 5xx failures
may retry within that bound. Authentication, permission, invalid-request/model, quota/429,
and other terminal 4xx failures stop immediately instead of spending the remaining budget.

Live detection is also bounded by `[detect].max_llm_regions_per_run` (six by default).
Before map/detect spend, `run` prints the all-files × three-lenses base-call projection and
the bounded plan. Region selection is ground-truth-blind: independently produced scanner
and architecture-map locations are considered first, with a stable path-derived,
directory-stratified sample reserved outside those signals. The sample is comparable
across pre-fix/post-fix trees and limits conventional test paths to 25% when enough
production paths exist. It does not make six sampled regions representative of every
file. The completion summary discloses selected and omitted regions; bounded coverage
must not be represented as a full-repository LLM review.

Each selected file+lens unit is checkpointed in SQLite. If detection stops, rerun the
standalone `repoauditor detect <repo-id>` command to receive a fresh usage budget; completed
units are reused without another provider call. A pipeline run whose total budget was
already exhausted must not be resumed for downstream paid stages under that same run id;
continue with the standalone `triage`, `falsify`, and `normalize` commands, each of which
opens its own bounded operation record.

More autonomous tool-using falsification is intentionally not enabled yet. The
[agentic escalation gate](docs/agentic-escalation-gate.md) requires authoritative usage
accounting, a protected real-world baseline, recall-safety evidence, read-only tools, and
independent claim verification before such a mode can become available.
The current deterministic certificate checker and its deliberately narrow structural
claims are documented in
[docs/security-claim-certificates.md](docs/security-claim-certificates.md).
The documentation authority map is [`docs/README.md`](docs/README.md). The detailed
historical execution ledger remains in
[`docs/project-priorities.md`](docs/project-priorities.md), while the evidence-backed hold
before parameter tuning is preserved in
[`docs/pre-tuning-readiness.md`](docs/pre-tuning-readiness.md).
Offline preparation and the exact later paid-calibration sequence are documented in
[docs/offline-readiness-runbook.md](docs/offline-readiness-runbook.md).

To test whether one falsification verdict survives increasing retrieval and iteration
resolution without changing its stored result:

```sh
uv run repoauditor falsify-convergence <finding-id>
uv run repoauditor falsify-convergence <finding-id> --format json
```

This evaluation makes multiple model calls and may incur API cost. It reports verdict
flips, citation overlap, confidence spread, and provider seed availability; it never writes
a finding or verdict. See the [convergence evaluation methodology](docs/convergence-evaluation.md).

To qualify the configured falsification instrument against fixed positive and negative
manufactured controls:

```sh
uv run repoauditor qualify-instrument
```

This paid, fail-closed control is also run automatically in the weekly live lane. A pass
applies only to the four sentinels and is not real-world accuracy evidence; the cases are
never injected into a user scan. See the
[manufactured-sentinel methodology](docs/manufactured-sentinels.md).

To qualify the versioned OWASP lens specifically against the manufactured vulnerable and
patched archive-extraction pair:

```sh
uv run repoauditor qualify-detection
uv run repoauditor qualify-detection --format json
```

This is a separate, opt-in paid check. It makes two logical model calls (bounded reliability
retries may add recorded attempts), exits nonzero unless the vulnerable Kotlin case is
raised and the normalized-containment control stays clean, and does not claim real-world
precision or recall.

To qualify OWASP v3 against a manufactured XML validation/consumption representation
mismatch and its same-verified-node control:

```sh
uv run repoauditor qualify-xml-detection
uv run repoauditor qualify-xml-detection --format json
```

This is also a two-logical-call, opt-in paid check. It does not execute XML or claim that
real parsers disagree, and it does not prove attacker control, signature failure, or
authentication bypass. In Actions, select the isolated `xml-detection-sentinels` scope.

## Output controls and automation

Global output flags must appear before the command:

```sh
# Default: progress plus concise stage summaries.
uv run repoauditor run <target>

# Only the final recap or an error.
uv run repoauditor --quiet run <target>

# Extra artifact and stage metadata.
uv run repoauditor --verbose run <target>

# Preserve Python tracebacks for troubleshooting unexpected failures.
uv run repoauditor --debug run <target>
```

Machine-readable output is opt-in:

```sh
uv run repoauditor repos list --format=json
uv run repoauditor review list <repo-id> --format=json
uv run repoauditor run <target> --format=ndjson
```

List commands return a JSON array. A long-running scan uses NDJSON—one JSON object per
line—so automation receives events as each stage starts, completes, or fails.

## Troubleshooting

- **`uv: command not found`** — install it with `brew install uv` on macOS or use the
  official uv installer on other systems, then open a new terminal.
- **Wrong Python version** — run `uv python install 3.12` followed by
  `uv sync --python 3.12`.
- **Missing Python packages** — run `uv sync --python 3.12`; do not use the system `pip`.
- **Missing API key** — export `ANTHROPIC_API_KEY`, or the variable named by
  `llm.api_key_env`, in the same terminal used to run the scan.
- **Model check fails** — verify the base URL, API key, model name, account access, and
  `response_format`. Start with `doctor --check-model`; use `--debug` only when a traceback
  is needed.
- **Scanner reported missing** — install the named scanner. The run remains usable, but
  its completion recap warns that coverage was incomplete.
- **No SQLite database** — no manual action is normally needed. `doctor` and `run`
  initialize it. `uv run repoauditor db init` is available for explicit repair/migration.
- **A run failed midway** — run the exact same target again to resume the failed stage. Use
  `runs list`/`runs show` to identify the error.
- **A run completed with deferred findings** — run `resume <repo-id>`. Repeat until its
  completion message points to review or finalize; upstream model stages are not repeated.
- **`finalize` is blocked** — first clear any deferred backlog with `resume <repo-id>`,
  then run `review list <repo-id>`, decide every open request, and retry `finalize`.

## Development checks

Install the locked development dependencies and run the required pull-request suite:

```sh
uv sync --python 3.12
uv run pytest -m "not integration and not live"
```

Scanner/calibration/chart tests and paid live-model tests are separate, automatically
enforced CI lanes:

```sh
uv run pytest -m "integration and not live"
REPOAUDITOR_LLM=live ANTHROPIC_API_KEY=... uv run pytest -m live
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for what each lane covers, its CI cadence, required
scanner binaries, safe API-secret setup, and the scheduled/manual public-corpus cache lane.
That lane acquires exact pinned public commits on a cache miss and runs corpus integrity
checks without executing upstream code or invoking a hosted model.

For pre-UAT validation, the manual `bounded corpus UAT` workflow offers a free four-language
scanner matrix and a separately acknowledged paid Anthropic run on the lightweight fixture.
Its artifacts preserve the distinction between independently sourced targets, unadjudicated
scanner candidates, and purpose-built fixture metrics. The paid fixture score counts only
confirmed, deduplicated issues, uses a model-applicable expected-case denominator, and
discloses disposition and severity checks separately; see [CONTRIBUTING.md](CONTRIBUTING.md).

`repoauditor db init` applies numbered migrations from `src/repoauditor/store/ddl/` and
is safe to rerun. Existing databases are upgraded in place; legacy quantitative scenarios
remain readable and new audited scenarios are linked to their simulation run. Ingest is
idempotent for an unchanged commit. Semgrep SARIF artifacts
are retained under `data/artifacts/<repo-id>/<commit>/detect/` and passed to triage
automatically.
