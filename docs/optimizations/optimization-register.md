# Optimization Register

Status: authoritative post-MVP work list as of 2026-07-29. POC acceptance is complete.

Current execution priorities

1. **OPT-001 — reviewed-label growth** resumes as the active evidence workstream now that
   scanner acquisition inputs have a required deployment gate. Prioritize non-CI
   positive-mechanism breadth; do not relax abstention, holdout, or evaluation-family
   controls merely to reach the numeric target.
2. **OPT-026 — historical scanner remeasurement** follows the assurance gate so invalidated
   historical zeros can be rerun without converting new candidates into automatic labels.
3. **OPT-002 — family-aware bootstrap ranges** follows only after OPT-001 produces adequate
   held-out family breadth and both classes.

OPT-022 through OPT-025 are implemented. OPT-003 through OPT-006 and OPT-008 through OPT-014
remain behind their documented evidence, budget, safety, or methodology gates. OPT-016 is
routine dependency maintenance. OPT-027 through OPT-030 remain ordered capability/scale work
behind the assurance and evidence gates above.

I. Evaluation and classifier maturity

   A. OPT-001 — Grow the reviewed label cohort to 100–200 with broader positive mechanisms
      — in progress/evidence-gated — owner: AppSec adjudication — source:
      `../triage-accuracy-roadmap.md` and `../project-priorities.md` — activate after MVP
      items are closed; preserve abstentions and frozen holdouts. The reusable
      `triage-acquisition-plan` command and frozen 2026-07-29 tranche prioritize
      least-reviewed rule families without inferring mechanisms or candidate outcomes;
      `triage-review-packet` verifies frozen provenance and renders bounded source evidence
      without recommending an outcome. The first 11-entry tranche was human-adjudicated,
      bringing the usable manual cohort to 69 labels but adding no actionable positives;
      the remaining local pool is dominated by repeated example/configuration negatives.
      The next acquisition pair is therefore frozen before scanner execution in
      `../../tests/fixtures/cve_positive_acquisition_cohort.json`: codecov-node
      CVE-2020-15123 adds a direct JavaScript command-injection target and patched control
      without entering an evaluation holdout. Its subsequent Semgrep Community run did not
      recover the command-injection target and emitted only the same two CI findings in both
      variants; the retained negative result is recorded in
      `../codecov-node-positive-acquisition-2026-07-29.json` and adds no labels. The
      materializer now supports an exact CVE-positive slug so future frozen pairs can be
      acquired without overwriting cached cohorts. Detector output still requires human
      adjudication. Follow-up execution validation found that Semgrep's default Git-ignore
      behavior excluded normal snapshots under the intentionally ignored `data/` tree while
      returning success. Parent/default Semgrep ignore discovery also excluded materialized
      corpus snapshots under `tests/fixtures`. The SAST adapter now passes both
      `--no-git-ignore` and an explicit snapshot `--project-root`, with an invocation
      regression test, so ingested source and corpus snapshots are actually scanned while
      any ignore policy inside the target snapshot remains effective. A simultaneous JSON
      target report now changes zero-target or malformed-target-report success into an
      explicit failed scanner status rather than a clean empty result. The
      [`execution audit`](../semgrep-execution-audit-2026-07-29.json) records the before/after
      bounded UAT: all nine runs changed from empty to complete and produced 1,263 Semgrep
      candidates, including the Juice Shop SQL-injection anchor. The broader
      [`deterministic-tool deployment audit`](../deterministic-tool-deployment-audit-2026-07-29.json)
      also corrected OSV-Scanner v2 invocation, hardened malformed-output and exit handling
      across SCA/secrets adapters, and exposes every scanner status. Its final nine-fixture
      matrix has no failed, partial, unavailable, or unexplained-zero run — DoD impact: none.
      OPT-001 execution has now resumed against five already-frozen vulnerable snapshots.
      The verified pinned Semgrep run scanned 826 targets and ingested 79 unassessed
      candidates; its immutable receipt is
      [`cve-positive-semgrep-acquisition-2026-07-29-v2.json`](../cve-positive-semgrep-acquisition-2026-07-29-v2.json).
      The adapter now normalizes retained SARIF rule IDs, rule names, and artifact URIs at
      the ingestion boundary so temporary configuration prefixes and host paths cannot
      fragment priors or leak into review artifacts. The v2 acquisition selector prioritizes
      production source, then deployment/configuration source, before supporting examples,
      docs, tests, and CI without using scores or outcomes. Its frozen
      [`11-entry review tranche`](../triage-review-acquisition-2026-07-29-v2.json) contains
      eight production and three deployment candidates. Human adjudication remains the next
      gate; no automatic labels were added. That tranche was subsequently adjudicated as
      eleven negatives, bringing the usable cohort to 80 labels (18 positive, 62 negative)
      across 12 engagements. Because the residual pool was low-yield supporting or repeated
      hardening evidence, the next expansion was frozen before execution in
      [`positive_mechanism_expansion_cohort.json`](../../tests/fixtures/positive_mechanism_expansion_cohort.json)
      and its [`protocol`](../opt-001-positive-mechanism-expansion-protocol-2026-07-29.json).
      The narrow anchors-only path excludes independent evaluation pairs. Three complete
      verified scans covered 2,195 targets, ingested 302 unassessed candidates, and recovered
      all three predeclared production targets: JavaScript and Java SQL injection plus Ruby
      unsafe deserialization. The immutable
      [`scan receipt`](../positive-mechanism-expansion-scan-2026-07-29.json) and frozen
      [`12-entry review tranche`](../triage-review-acquisition-2026-07-29-v3.json) add no
      automatic labels. Retained SARIF notification text is now canonicalized alongside
      rule metadata and paths — DoD impact: none.

   B. OPT-002 — Family-aware bootstrap ranges — deferred — owner: ML evaluation — source:
      `../triage-accuracy-roadmap.md` — activate after adequate held-out family breadth and
      both classes exist — DoD impact: none.

   C. OPT-003 — Temporal validation — deferred — owner: ML evaluation — source:
      `../triage-accuracy-roadmap.md` — activate after meaningful chronological depth exists
      — DoD impact: none.

   D. OPT-004 — Identical-input provider repeatability characterization — deferred/paid —
      owner: evaluation engineering — source: `../convergence-evaluation.md` and
      `../pre-tuning-readiness.md` — activate after a frozen repeat protocol and budget are
      approved — DoD impact: none.

II. Operations and cost

   A. OPT-005 — Formal same-store three-run usage calibration — deferred/paid — owner:
      reliability engineering — source: `../offline-readiness-runbook.md` — activate after
      MVP closure or if current hard ceilings block the POC walkthrough — DoD impact: none
      while limits remain fail-closed.

   B. OPT-006 — Provider dollar-cost reporting — deferred/source-gated — owner: reliability
      engineering — source: `../project-priorities.md` — activate only with dated,
      versioned provider/model pricing — DoD impact: none.

III. Detection and falsification depth

   A. OPT-007 — Improve production-region selection — implemented offline
      — owner: detection engineering — source:
      `../untouched-production-selection-plan-2026-07-28.json` and
      `../plotly-untouched-production-selection-2026-07-28.json` — the untouched Plotly.js
      measurement omitted the reviewed target in both variants, consistent with prior
      development-only aiohttp/Rack omissions. Begin only with a frozen, general path-blind
      design and offline replay against retained artifacts; never tune to any revealed
      target path. The frozen
      [`v2 protocol`](opt-007-production-region-selection-v2.md) reserves one existing
      region for syntactic caller/callee neighbors of exact architecture-map locations
      while preserving the total cap and stable blind sampling. Generic regressions and the
      [`offline replay`](opt-007-offline-replay-2026-07-29.json) exercised both neighbor
      bases without target metadata or provider calls. Live or paid validation requires a
      separately approved protocol and budget — DoD impact: none because the current DoD
      requires measurement, not a passing selection outcome.

   B. OPT-008 — Expand slicing and deterministic certificates across additional clients,
      frameworks, languages, and cross-file flows — deferred/evidence-gated — owner: AppSec
      engineering — source: `../security-claim-certificates.md` and
      `../triage-accuracy-roadmap.md` — activate for specific corpus misses — DoD impact:
      none.

   C. OPT-009 — In-family/out-of-family novelty prioritization — deferred/data-gated —
      owner: AppSec/ML evaluation — source: `../project-priorities.md` — activate after
      enough manually reviewed LLM findings demonstrate held-out benefit — DoD impact: none.

   D. OPT-010 — Agentic falsification — deferred — owner: AppSec architecture — source:
      `../agentic-escalation-gate.md` — activate only after every documented safety and
      evaluation prerequisite passes — DoD impact: none.

IV. Quantitative enrichment

   A. OPT-011 — Sourced correction of organization-frequency allocation — methodology-gated
      — owner: quantitative-methodology — source: `../quantitative-integrity-audit.md` —
      long-term activation requires a defensible allocation/decomposition. The MVP separately
      gates affected output as experimental and not decision-grade — DoD impact: MVP
      presentation gate completed; richer model remains optimization.

   B. OPT-012 — Dated cached EPSS/KEV enrichment — deferred/network- and source-gated —
      owner: threat-data engineering — source: `../prior-scope-roadmap.md` — activate only
      for real CVEs with defined stale/offline behavior — DoD impact: none.

   C. OPT-013 — Prior temporal metadata and population applicability — deferred/source-gated
      — owner: quantitative-methodology — source: `../prior-scope-roadmap.md` — activate
      after exact source metadata is verified — DoD impact: none beyond current disclosure.

   D. OPT-014 — Prior-predictive checks, held-out validation, hierarchical priors,
      backtesting, and portfolio optimization — deferred/data-gated — owner:
      quantitative-methodology — source: `../prior-scope-roadmap.md` — activate only with
      applicable organization/incident data — DoD impact: none.

V. Intake

   A. OPT-015 — Preserve deterministic scanner failure detail — implemented as an MVP
      acceptance correction —
      owner: reliability engineering — source: the Plotly.js blind capture initially
      produced `semgrep_status=failed` when `--config auto` could not resolve through the
      restricted network sandbox, but the adapter artifact retained no root cause. Improve
      diagnostics without changing graceful degradation. The failed POC walkthrough then
      demonstrated direct DoD impact: installed `pip-audit` failed at execution while
      preflight called the toolchain ready. Scanner execution status and attributable detail
      are now retained; an exact-direct-pin fallback is visibly partial rather than full
      transitive coverage.

   B. OPT-016 — Remove SHAP/Matplotlib pending-deprecation noise — newly surfaced/deferred
      — owner: test infrastructure — source: the 2026-07-28 fast-lane run completed with
      three warnings from SHAP's use of deprecated Matplotlib colormap mutation methods.
      Track the upstream dependency upgrade rather than patching third-party code; no
      correctness impact was observed — activation: routine dependency maintenance after
      MVP closure — DoD impact: none.

   C. OPT-017 — Diagnose the UAT IDOR selection/detection miss — completed diagnosis —
      owner: detection evaluation — source:
      `../poc-acceptance-attempt-2026-07-28.md` and
      `../poc-acceptance-walkthrough-2026-07-28.md` — the Anthropic rerun confirmed that
      `storefront/orders.py` was omitted by the bounded primary region plan while cross-file
      context still recovered and validly cited the IDOR. This is evidence that selected
      region scope and retrieval/citation scope differ, not grounds for target-path tuning.
      Feed the generalizable planner evidence into OPT-007 — DoD impact: none.

   D. OPT-018 — Support explicit requirements files in OSV-Scanner integration —
      implemented in the first post-MVP optimization PR — owner: deterministic detection —
      source: `../poc-acceptance-walkthrough-2026-07-28.md` — OSV-Scanner 2.4.0 returned
      “No package sources found” for recursive directory scanning even though a root
      `requirements.txt` existed; an explicit lockfile check parsed it successfully. Add a
      bounded manifest-discovery path with adapter regression coverage, preserving
      failure/partial-coverage disclosure. The adapter now retries a bounded set of explicit
      `requirements*.txt` files only after the attributable recursive-discovery failure and
      labels successful fallback coverage partial — DoD impact: none because pip-audit
      completed and the original degradation was disclosed.

   E. OPT-019 — Persist and expose rich per-stage summaries for demo/resume runs —
      implemented — owner: CLI/store observability — source:
      `../poc-acceptance-walkthrough-2026-07-28.md` — the region plan existed in
      `detection_region_run` but `runs show` did not expose it for the demo lineage, forcing
      a direct store query. Demo now records each executed stage, while `run`, `resume`, and
      direct map/detect/falsify/normalize commands share the same applicable summary
      projections. `runs show` exposes selected regions, scanner status/failure detail,
      model/prompt provenance, counts, and artifacts without a direct store query — DoD
      impact: none; live coverage was disclosed during acceptance.

   F. OPT-020 — Document and test bounded-plan versus cross-file retrieval scope —
      implemented in PR #59 (merge commit `5e07c58`) — owner: detection architecture — source:
      `../poc-acceptance-walkthrough-2026-07-28.md` — a valid IDOR citation referenced
      `storefront/orders.py` although that file was absent from the six selected primary
      regions. `../detection-context-provenance.md` now distinguishes architecture-based
      primary selection from the bounded syntactic caller/similarity context that may append
      an external file. Detection results and stage summaries retain only the expansions
      actually appended, with basis/file/line/symbol provenance. Generic path-blind
      regressions protect the behavior; no observed target path became a selection rule —
      DoD impact: none.

   G. OPT-021 — Generate a box-drawing/graphical architecture layout — implemented
      — owner: mapping presentation — source:
      `../poc-acceptance-walkthrough-2026-07-28.md` and the retained acceptance architecture
      artifact — the current text schematic is accurate and useful but renders each flow as
      a separate linear sentence. Add a deterministic, terminal-safe box-drawing projection
      that makes shared trust boundaries, entry points, datastores, and integrations
      visually scannable. Preserve the existing plain-text inventory and explicit
      “not recovered” limitations; do not infer new edges merely to improve layout. Consider
      an optional graphical format only if it can be generated offline without expanding
      mapping business logic — activation: satisfied by the merged OPT-018 through OPT-020
      sequence. The architecture artifact now opens with a deterministic terminal-safe
      projection that groups entry points under shared recovered trust boundaries, renders
      integration direction, and leaves datastores visibly unconnected. The original
      relationship and entity inventories remain intact, with focused presentation and CLI
      regressions — DoD impact: none.

VI. Deterministic scanner assurance and capability

   A. OPT-022 — First-class scanner execution contract — highest/immediate — owner:
      reliability engineering — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` and
      `../scanner-execution-contract.md` — define one durable contract
      across Semgrep, gitleaks, pip-audit, and OSV-Scanner covering applicability, exact
      invocation/version, process exit, targets or manifests scanned, output-schema
      validation, finding count, skipped-target reasons, partial coverage, status, and
      attributable failure detail. A zero is clean only when execution is complete,
      applicable targets were actually scanned, and validated output contains no findings;
      otherwise report `not-applicable`, `partial`, `unavailable`, or `failed`. PR #64
      implements the first corrections: Semgrep target verification, OSV-Scanner v2
      invocation, producer-specific JSON validation, and all-tool bounded-UAT status
      visibility. The typed contract now rejects unverified clean zeros and persists
      applicability, validated-output state, findings, target/manifest count and count basis,
      available version/configuration provenance, and failure detail through detect summaries
      and resume reconstruction. Activation: satisfied for the common contract; OPT-023 and
      OPT-024 add canaries and complete provenance before new acquisition evidence is
      interpreted — DoD impact: none.

   B. OPT-023 — Per-scanner deployment canaries — implemented — owner: reliability and
      detection engineering — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` and
      `../scanner-deployment-canaries.md` — pass a small positive and
      clean/not-applicable control through each production adapter invocation: a
      language-appropriate Semgrep syntax/rule control, a synthetic gitleaks credential, a
      pinned vulnerable and clean pip-audit manifest, and vulnerable/clean OSV lockfiles.
      Canary results are execution-health evidence only and must never enter the product
      finding store, classifier labels, evaluation metrics, or human-review acquisition.
      The `scanner-canaries` command now exercises all four adapter subprocess/parser paths,
      fails closed on either control, reports the typed execution contract, deletes temporary
      inputs, and cannot persist findings. The OSV clean-side control intentionally asserts
      `not-applicable` for a root without a supported manifest so it cannot be confused with
      a scanned clean zero. Activation: satisfied after OPT-022; OPT-024 remains responsible
      for production ruleset and advisory-database provenance — DoD impact: none.

   C. OPT-024 — Pin scanner configuration and retain provenance — implemented — owner: detection
      release engineering — source:
      `../semgrep-execution-audit-2026-07-29.json` and
      `../scanner-provenance.md` — replace mutable Semgrep `--config auto`
      as the production evidence baseline with a reviewed, versioned ruleset reference or
      retained digest; record binary version, rule count/digest, registry resolution
      outcome, and applicable advisory-database timestamp/version for every scanner run.
      Evaluate upgrades separately against frozen controls before promotion and preserve
      offline/stale behavior. Semgrep now verifies a vendored snapshot and retained digest
      of the official default registry payload before invoking the scanner, supporting
      offline execution and failing closed on package corruption. All adapters retain
      normalized invocation and available binary
      version; Semgrep retains digest/rule count/resolution, gitleaks identifies its
      binary-embedded default, and SCA retains authoritative advisory-source identity and
      UTC query time. PyPI and OSV do not expose an immutable database release in these
      responses, so version remains explicitly null rather than inferred. Activation:
      satisfied after OPT-022; OPT-025 promotes these assertions to CI — DoD impact: none.

   D. OPT-025 — Required scanner deployment gates — implemented — owner: CI/reliability engineering
      — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` and
      `../scanner-deployment-gate.md` — add a fast required CI lane
      that asserts scanner startup, canary outcomes, nonzero applicable target counts,
      parseable output schemas, version/config provenance, and absence of unexplained zeros.
      Keep the larger public-corpus scan scheduled/manual because it is slower and
      registry/network dependent; publish its complete per-tool status matrix and retain raw
      artifacts. The stable `scanner deployment / required` job now runs for pull requests,
      main pushes, and manual test dispatches with exact scanner versions. Canary schema v2
      fails closed on positive/negative execution or scanner-specific provenance, publishes
      the report to the step summary, and retains raw JSON and version evidence for 30 days.
      The larger corpus matrix remains manual. Activation: satisfied after OPT-022 through
      OPT-024; repository branch protection should require the stable job name — DoD impact:
      none.

   E. OPT-026 — Rerun and qualify historical scanner evidence — high/evidence repair —
      owner: detection evaluation — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` — mark the three identified
      historical zero-result Semgrep artifacts coverage-invalid without deleting them, then
      rerun material historical snapshots through the pinned, canary-qualified adapters.
      Report candidate and status deltas; do not retroactively turn newly emitted candidates
      into labels, ground truth, or evaluation positives. Activation: after OPT-025 — DoD
      impact: none.

   F. OPT-027 — RepoAuditor-owned supplemental Semgrep pack — medium/high,
      evidence-gated — owner: AppSec detection engineering — source:
      `../codecov-node-positive-acquisition-2026-07-29.json` — add a narrow reviewed pack for
      high-value sinks the public rules demonstrably miss, beginning with variable or
      concatenated shell execution and paired vulnerable/patched controls; consider direct
      SQL construction, URL-fetch SSRF, unsafe archive extraction, and filesystem traversal
      only with equally defensible controls. Supplemental matches remain review candidates,
      not automatic actionable findings. Activation: after OPT-024 pins the baseline and
      OPT-026 establishes corrected historical behavior — DoD impact: none.

   G. OPT-028 — Advisory-target pre/post differential checks — medium — owner: detection
      evaluation — source:
      `../codecov-node-positive-acquisition-2026-07-29.json` and
      `../semgrep-execution-audit-2026-07-29.json` — classify each frozen target as
      vulnerable-only recovery, stable pre/post mechanism signal, patched-only signal, or
      complete miss. Never count a signal that persists after the isolated patch as precise
      target recovery merely because its file/citation overlaps; preserve unrelated
      candidates as unadjudicated. Activation: alongside OPT-027 rule qualification — DoD
      impact: none.

   H. OPT-029 — Candidate explosion and repetition controls — medium/scale-gated — owner:
      AppSec workflow engineering — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` — the corrected bounded run
      produced 1,941 raw candidates. Add disclosed, deterministic collapse by exact pre/post
      identity, rule/normalized sink/location deduplication, repeated-family caps per
      engagement, and explicit generated/vendor/docs/example path policy. Preserve raw
      artifacts and publish every suppression count; never suppress by predicted outcome or
      hidden answer key. Activation: before producing the next large human-review packet —
      DoD impact: none.

   I. OPT-030 — Per-tool capability and applicability matrix — medium/documentation —
      owner: detection architecture — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` — publish the mechanisms,
      ecosystems, manifest/source prerequisites, expected strengths, known blind spots, and
      meaning of `complete`, `empty`, and `not-applicable` for every deterministic tool.
      Keep deployment health separate from recall/precision claims and link each capability
      statement to a control or retained measurement. Activation: draft with OPT-022 and
      finalize after OPT-026/OPT-028 evidence — DoD impact: none.

   J. Add the next proposed improvement as `OPT-031`; do not place it directly into the MVP
      recovery plan unless the project owner explicitly changes the DoD.
