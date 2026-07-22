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
2. **map** — identifies entry points, data stores, integrations, and trust boundaries;
3. **detect** — runs model lenses and available deterministic scanners;
4. **triage** — ranks likely actionable findings and suppresses weak signals;
5. **falsify** — tries to disprove each candidate;
6. **normalize** — reconciles evidence and routes uncertainty to review.

The run intentionally stops after normalization. It never silently skips the review
checkpoint and proceeds to final reports.

## How the decision engine works

`repoauditor` treats scanner and model output as candidate evidence, not as an automatic
verdict. The decision path is deliberately staged:

1. **Detection gathers independent signals.** Model lenses and deterministic scanners
   contribute findings with source attribution and code citations. Multiple reports of the
   same issue are retained as corroborating evidence rather than counted as separate risks.
2. **Triage ranks actionability.** The classifier estimates `P(actionable)` and records its
   feature attribution. This probability represents uncertainty that a finding is real and
   useful—not technical severity and not an expected incident frequency.
3. **Falsification challenges the candidate.** A bounded evidence loop checks reachability,
   attacker control, and mitigating controls. It confirms, kills, defers, or leaves the
   candidate unresolved; it never silently drops an inconclusive result.
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
uv run repoauditor triage-collection        # progress toward the real-label activation gate
```

Below 40 real scored labels, this command deliberately withholds the curve. Engagement-
grouped validation additionally requires at least eight distinct repositories. A small,
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

`uncertain` assessments are retained in an append-only audit history but never enter model
training. For `true_positive` or `false_positive`, the assessment also updates the effective
manual label. Repeat `--dimension` with analyst-verified coverage descriptors such as
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

# Inspect run history or the failure details for one run.
uv run repoauditor runs list --repo-id <repo-id>
uv run repoauditor runs show <run-id>

# Resume an interrupted run automatically.
uv run repoauditor run <same-path-or-url>

# Ignore an incomplete prior run and start a separate run record.
uv run repoauditor run <path-or-url> --fresh
```

Map, detect, and normalize use idempotent writes, so a partially completed stage can be
rerun without duplicating its persisted records. Existing downstream finding verdicts are
preserved. Run history records stage status, timing, artifacts, and attributable failures.

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
- **A run stopped midway** — run the exact same target again to resume. Use
  `runs list`/`runs show` to identify the failed stage and error.
- **`finalize` is blocked** — run `review list <repo-id>`, decide every open request, and
  retry `finalize`.

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
scanner candidates, and purpose-built fixture metrics; see [CONTRIBUTING.md](CONTRIBUTING.md).

`repoauditor db init` applies numbered migrations from `src/repoauditor/store/ddl/` and
is safe to rerun. Existing databases are upgraded in place; legacy quantitative scenarios
remain readable and new audited scenarios are linked to their simulation run. Ingest is
idempotent for an unchanged commit. Semgrep SARIF artifacts
are retained under `data/artifacts/<repo-id>/<commit>/detect/` and passed to triage
automatically.
