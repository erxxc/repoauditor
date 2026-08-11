# Optimization Register

Status: authoritative post-MVP work list as of 2026-08-01. POC acceptance is complete.

Current execution priorities

OPT-035 publishes the canonical machine-readable lifecycle ledger at
[`optimization-status.json`](optimization-status.json). It records 31 closed and 4 open
items. Every open item remains subject to its activation gate; priority does not waive it.
The dated [`outstanding-work checkpoint`](outstanding-work-checkpoint-2026-08-07.json)
records every open optimization, tuning blocker, and nonblocking future expansion before
the next paid OPT-005 batch; the accepted POC Definition of Done remains complete.

| Priority | Open item | Gate |
|---:|---|---|
| 1 | OPT-002 — family-aware bootstrap ranges | data |
| 2 | OPT-003 — temporal validation | data |
| 3 | OPT-009 — novelty prioritization | data |
| 4 | OPT-014 — predictive checks and portfolio modeling | data |
| 5 | OPT-010 — agentic falsification | safety and evaluation |

OPT-001, OPT-004 through OPT-008, OPT-011 through OPT-013, and OPT-015 through OPT-035 are closed at their approved scope. Optional
expansion of a closed bounded scope must be proposed as new work rather than silently
reopening its lifecycle state.

I. Evaluation and classifier maturity

   A. OPT-001 — Grow the reviewed label cohort to 100–200 with broader positive mechanisms
      — implemented at lower maturity bound — owner: AppSec adjudication — source:
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
      rule metadata and paths. Human review of that tranche added nine actionable positives
      and three negatives, bringing the cohort to 92 usable labels (27 positive, 65
      negative) across 15 engagements. The final
      [`12-entry production tranche`](../triage-review-acquisition-2026-07-29-v4.json)
      targets authorization, path/file handling, redirects, token secrets, and template
      output while excluding documentation, vendor bundles, CI, and package hygiene. Human
      review added ten actionable positives and two negatives. OPT-001 therefore closes at
      104 usable manual labels (37 positive, 67 negative) across 15 engagements, with three
      abstentions preserved. The evaluation-compatible scored subset remains 36 labels and
      does not activate OPT-002; benchmark acquisition is not reclassified as held-out
      evidence — DoD impact: none.

   B. OPT-002 — Family-aware bootstrap ranges — implemented — owner: ML evaluation — source:
      `../triage-accuracy-roadmap.md` — activate after adequate held-out family breadth and
      both classes exist. The
      [`independent acquisition protocol`](opt-002-independent-acquisition-protocol-2026-08-07.json)
      freezes two primary product repositories and one conditional reserve at exact commits
      before scanning. It requires the current 3.3.0 score identity before blinded human
      review, excludes all existing benchmark/CVE/protected/UAT families, and fails closed
      on identity drift or an undersized 8–12-entry packet. The protocol authorizes no
      materialization, scanning, provider transfer, store mutation, review outcome, or model
      change. The pending
      [`primary execution receipt`](opt-002-primary-execution-receipt-2026-08-07.json)
      now fixes exact-commit ingest, deterministic-only detection, compatible scoring,
      zero provider usage, resource ceilings, stop conditions, and complete result evidence
      for the two primaries. It excludes the reserve and all review activity; explicit
      execution authorization was granted. The first
      [`execution attempt`](opt-002-primary-execution-attempt-2026-08-07.json) passed the
      scanner canary, exact-commit Documenso ingest, deterministic scan, and zero-provider
      accounting, then stopped before Lobsters because triage selected randomforest 1.9.0
      instead of the frozen xgboost 3.3.0 identity. Seven previously unharvested derived
      labels from the byte-identical lightweight identity changed the training corpus from
      111 to 118 rows. No Documenso human labels were added; the duplicate-family corpus
      must be reconciled before retry or protocol amendment. The
      [`duplicate reconciliation`](opt-002-duplicate-reconciliation-2026-08-07.json)
      now binds both lightweight aliases to one explicit evaluation family and gives exact
      family/rule/fingerprint copies one effective contribution in training and rule priors,
      while retaining every historical row. Contradictory copies fail closed. Read-only
      live-store verification restores 111 effective rows (104 manual, 7 derived) and the
      frozen xgboost selection. The pending
      [`zero-provider continuation receipt`](opt-002-zero-provider-continuation-receipt-2026-08-07.json)
      freezes retained-artifact Documenso re-triage and conditionally permits exact-commit
      Lobsters deterministic acquisition only after the full scoring identity passes. It
      requires a new store backup, unchanged 1,473-row provider-usage ledger, and complete
      result evidence; reserve activation, packet selection, review, providers, tuning, and
      gate promotion remain excluded. The
      [`continuation result`](opt-002-zero-provider-continuation-result-2026-08-07.json)
      records successful XGBoost 3.3.0 scoring for retained Documenso and exact-commit
      Lobsters, healthy deterministic scanners, and zero provider activity. The primaries
      yield 218 unique production/deployment candidates before selection, so the reserve is
      not activated. No packet identities were selected or exposed and no labels were added;
      OPT-002 is now packet-gated. The pending
      [`packet-selection receipt`](opt-002-packet-selection-receipt-2026-08-07.json)
      freezes a deterministic, balanced 12-entry selection over the two primary families.
      It forbids score and outcome fields, permits identity disclosure only in the persisted
      plan/result, and excludes source rendering, review, labels, network/provider activity,
      reserve activation, tuning, and promotion. The
      [`packet-selection result`](opt-002-packet-selection-result-2026-08-07.json)
      records one successful offline selection: 12 unique identities, six per primary
      family, with a byte-identical store and no forbidden output fields, network/provider
      activity, assessments, or labels. OPT-002 is now review-gated — DoD impact: none.
      The pending
      [`bounded review receipt`](opt-002-bounded-review-receipt-2026-08-08.json)
      freezes digest-checked rendering of at most 20 adjacent lines for each selected
      identity and explicit project-owner dispositions with abstention. It excludes
      follow-up expansion, store writes, automatic labels, providers, rescoring, tuning,
      reserve activation, and promotion.
      The authorized
      [`bounded review result`](opt-002-bounded-review-result-2026-08-10.json) records all
      12 explicit responses: 11 decided projections (five actionable and six
      non-actionable) plus one preserved abstention. The minimum-label and two-class review
      conditions pass, while the byte-identical store, zero provider activity, and zero
      labels confirm that import and OPT-002 status remain separately gated.
      The pending
      [`review import receipt`](opt-002-review-import-receipt-2026-08-10.json) freezes one
      atomic 12-assessment/11-label import and a read-only post-import gate report. It
      preserves the abstention without a label and excludes response changes, providers,
      rescoring, training, tuning, reserve activation, production-policy changes, and
      OPT-002 promotion or closure.
      The authorized
      [`review import result`](opt-002-review-import-result-2026-08-10.json) records one
      atomic transaction: 12 assessments, 11 manual labels, five positive, six negative,
      and one label-free abstention. The compatible cohort is now 47 labels across nine
      genuine evaluation families with both classes represented, satisfying the frozen
      data gate. OPT-002 remains open pending a separate promotion decision.
      Gate satisfaction activates, rather than completes, the approved roadmap scope. The
      pending [`bootstrap implementation receipt`](opt-002-bootstrap-implementation-receipt-2026-08-10.json)
      freezes deterministic 2,000-resample, 95% percentile ranges using evaluation families
      as sampling units. It preserves descriptive point estimates and excludes automatic
      threshold selection, training, tuning, rescoring, policy changes, providers, and store
      mutation.
      The authorized
      [`implementation result`](opt-002-bootstrap-implementation-result-2026-08-10.json)
      reports deterministic 95% family-block ranges for all fixed thresholds over 47
      compatible human labels and nine evaluation families. The CLI remains descriptive,
      selects no threshold, and withholds ranges below the label/family/class gate. OPT-002
      is closed at this bounded scope; further methods or policy use require new scope.

   C. OPT-003 — Temporal validation — deferred — owner: ML evaluation — source:
      `../triage-accuracy-roadmap.md` — activate after meaningful chronological depth exists
      — the dated
      [`temporal validation protocol`](opt-003-temporal-validation-protocol-2026-08-10.json)
      identifies only one leakage-safe prospective wave: 11 decided labels across two
      families, scored on August 7 and reviewed on August 10. Earlier compatible labels
      were outcome-known before scoring and remain retrospective only. Activation requires
      40 prospective decided labels, eight families, both classes, and two separately
      frozen prediction waves. Acquisition and execution remain separately gated — DoD
      impact: none.
      The pending
      [`wave-one prediction receipt`](opt-003-wave-1-prediction-receipt-2026-08-10.json)
      freezes one model before acquisition from the current 122-label effective corpus and
      exact commits of three outcome-blind product families: Chatwoot, Linkwarden, and
      Paperless-ngx. It stops after compatible persisted predictions; packet selection,
      review, assessments, labels, providers, tuning, and policy changes remain excluded.
      The authorized [`wave-one attempt`](opt-003-wave-1-attempt-2026-08-10.json) froze the
      exact 122-label model, then stopped before acquisition because required scanner
      canaries failed. Gitleaks passed; Semgrep, supplemental Semgrep, pip-audit, and the OSV
      positive control did not. The generic canary also attempted PyPI/OSV-backed checks
      outside the GitHub-only boundary, recorded as a protocol breach. The store remained
      byte-identical and no repository, prediction, assessment, or label was created.
      The pending
      [`corrected retry receipt`](opt-003-wave-1-corrected-receipt-2026-08-11.json) binds
      Semgrep logging to the writable retry artifact directory and adds explicit scanner
      selection. Offline Semgrep/supplemental/Gitleaks controls are separated from named
      PyPI/OSV advisory-host checks. A new model is required after both pass; the stopped
      model, review, outcomes, providers, tuning, and policy changes remain excluded.

   D. OPT-004 — Identical-input provider repeatability characterization — implemented —
      owner: evaluation engineering — source: `../convergence-evaluation.md`,
      `../pre-tuning-readiness.md`, and the frozen
      [`repeatability protocol`](opt-004-repeatability-protocol-2026-08-01.json). The initial
      characterization fixes the existing standard falsification profile across three fresh
      observations of each of two predeclared human-reviewed subjects. Immutable input and
      configuration digests prevent resolution or corpus changes from being mislabeled as
      provider variance. Verdict, citation, confidence, evidence size, tokens, latency, and
      dated cost are descriptive; no success threshold or automatic production change is
      allowed. The [`execution receipt`](opt-004-repeatability-execution-receipt-2026-08-02.json)
      freezes findings 295/300, their shared snapshot, architecture and retrieval digests,
      and an approved aggregate ceiling of 72 calls, 250,000 provider-reported tokens, and
      $6.25. The complete [`result`](opt-004-repeatability-result-2026-08-02.json) used 24
      calls, 136,954 provider-reported tokens, and $0.832270. Finding 295 was confirmed in
      all three observations and finding 300 was killed in all three; both had pairwise
      citation Jaccard 1.0. Confidence varied only for 295 (range 0.05; population standard
      deviation 0.02357). This descriptive result closes the approved scope and changes no
      production threshold or verdict — DoD impact: none.

II. Operations and cost

   A. OPT-005 — Formal same-store three-run usage calibration — completed — owner:
      reliability engineering — source: `../offline-readiness-runbook.md` — activate after
      MVP closure or if current hard ceilings block the POC walkthrough — DoD impact: none
      while limits remain fail-closed. The following is a chronological execution record;
      intermediate `open`, `pending`, and `unstarted` statements describe their dated step,
      not current OPT-005 state. The first newly authorized
      [`lightweight attempt`](opt-005-lightweight-attempt-2026-08-01.json) stopped safely at
      27 calls, 100,177 provider-reported tokens, and $0.642125. It retained 111 deferred
      findings, so it does not qualify and the protected pair was not started. A stage-summary
      datetime serialization defect surfaced after paid detection; the correction resumed
      the same run and reused all 18 completed detection calls without rebilling them.
      An offline [`queue replay`](opt-005-falsification-queue-replay-2026-08-02.json) then
      found 60 conservative issue groups across those 111 rows and removed 51 redundant
      future challenges while retaining every finding and explicit propagation provenance.
      Advisory namespaces remain separate where detector alias evidence was not retained.
      The descriptive continuation projection falls from 222 to 120 calls; it is not an
      authorization. A frozen [`lightweight continuation receipt`](opt-005-lightweight-continuation-receipt-2026-08-02.json)
      proposes at most 16 linked batches, 180 aggregate calls, 600,000 provider-reported
      tokens, and $5.00 while preserving the existing per-batch breakers and production
      retry policy. The authorized [`continuation attempt`](opt-005-lightweight-continuation-attempt-2026-08-02.json)
      stopped after two completed batches and one partial failed batch when two 120-second
      provider timeouts created unknown-usage rows. It retained 38 attempts, 36 priced calls,
      107,076 known tokens, at least $0.726340, and 61 deferred rows; protected snapshots
      were not started. The partial batch exposed finding 570 as deferred despite persisted
      iterations. The queue now converts an interrupted, already-examined representative to
      explicit unresolved before re-raising, and finding 570 was reconciled with the retained
      run/usage provenance, leaving 60 deferred rows. New authorization remains required —
      DoD impact: none. A smaller [`connectivity retry receipt`](opt-005-connectivity-retry-receipt-2026-08-06.json)
      freezes the corrected 60-row/52-group queue and proposes at most two batches, 36 calls,
      120,000 provider-reported tokens, and $1.00. It stops on the first unknown-usage
      attempt and excludes both protected snapshots. The authorized
      [`retry result`](opt-005-connectivity-retry-result-2026-08-06.json) completed one clean
      batch (18 calls, 45,638 tokens, $0.312050, zero unknown usage), then stopped because
      production preflight included an unexamined unresolved row omitted by the deferred-only
      receipt. Production and future receipts now share the exact pending predicate. The
      residual queue is 55 rows/51 groups. A corrected
      [`pending-queue retry receipt`](opt-005-pending-queue-retry-receipt-2026-08-07.json)
      freezes that complete selection domain and proposes two batches, 36 calls, 120,000
      provider-reported tokens, and $1.00. It excludes the protected pair and remains
      authorization-pending. The authorized
      [`pending-queue retry result`](opt-005-pending-queue-retry-result-2026-08-07.json)
      completed one clean batch using 22 calls, 57,041 tokens, and $0.395765 with zero
      unknown usage. It stopped before batch two because only 14 calls remained—below the
      recent 18–22 call batch range. The residual queue is 51 rows/47 groups, all deferred;
      new authorization is required. The next
      [`single-batch receipt`](opt-005-single-batch-receipt-2026-08-07.json) freezes that
      queue and proposes one batch capped at 26 calls, 75,000 provider-reported tokens, and
      $0.55. Its budget and bounded evidence transfer to Anthropic remain separately
      authorization-pending; protected snapshots are excluded. The authorized
      [`single-batch result`](opt-005-single-batch-result-2026-08-07.json) completed with 18
      calls, 46,662 tokens, $0.328710, and zero unknown usage. The residual queue is 47
      deferred rows/43 groups. The next
      [`single-batch receipt`](opt-005-single-batch-2-receipt-2026-08-07.json) retains the
      same 26-call/75,000-token/$0.55 limits. Its authorized
      [`result`](opt-005-single-batch-2-result-2026-08-07.json) completed as run 19 with 6
      calls, 15,533 tokens, $0.103185, and zero unknown usage. The residual production
      queue is 46 deferred rows/42 groups. Protected snapshots remain unstarted and any
      further batch requires new authorization. The agreed
      [`lightweight completion receipt`](opt-005-lightweight-completion-receipt-2026-08-07.json)
      freezes that residual queue and proposes aggregate ceilings of 42 batches, 270 calls,
      750,000 provider-reported tokens, and $5.50, with 26-call/75,000-token/$0.55 per-batch
      breakers. Authorization and bounded evidence transfer remain pending; protected
      snapshots are excluded. The dated
      [`closeout reassessment`](opt-closeout-reassessment-2026-08-07.json) preserves the
      sequence and gates for all seven open optimizations. The authorized
      [`lightweight completion result`](opt-005-lightweight-completion-result-2026-08-07.json)
      then drained the exact queue through runs 20–61: 42 completed batches, 230 calls,
      617,286 provider-reported tokens, $4.228910, and zero unknown usage. Run 61 completed
      normalization and opened 51 review requests; the production pending queue is zero.
      Protected snapshots remain unstarted, and OPT-005 stays open pending their separate
      protocol plus the offline three-run comparison. The next
      [`protected pre-fix receipt`](opt-005-protected-pre-receipt-2026-08-07.json) freezes
      only serialize-javascript commit `3bab6dee8db7317310a97af5d28f0f0479d21930`
      and proposes at most three linked batches, 225 calls, 750,000 provider-reported
      tokens, and $5.00. Authorization and protected evidence transfer remain pending; the
      post-fix snapshot is explicitly excluded.
      The authorized [`pre-fix result`](opt-005-protected-pre-result-2026-08-07.json)
      completed runs 62–64 using 74 calls, 230,595 provider-reported tokens, $1.503015,
      and zero unknown usage, then stopped at the three-batch ceiling with 44 deferred
      findings. The current OSV-backed scan produced 55 advisory candidates, so the
      historical two-batch observation did not predict the present queue. This is not a
      terminal calibration observation; post-fix remains untouched and any continuation
      requires a new frozen receipt. The
      [`pre-fix continuation receipt`](opt-005-protected-pre-continuation-receipt-2026-08-07.json)
      freezes the 44-row/44-group residual queue at run 64 and proposes 11 continuation
      batches, 275 calls, 750,000 provider-reported tokens, and $5.50. Authorization and
      protected residual evidence transfer remain pending; post-fix stays excluded.
      The authorized [`continuation result`](opt-005-protected-pre-continuation-result-2026-08-07.json)
      drained the queue through runs 65–75 using 256 calls, 638,056 provider-reported
      tokens, $4.516240, and zero unknown usage. The complete pre-fix chain is runs 62–75:
      330 calls, 868,651 tokens, $6.019255, and zero deferred findings. Run 75 normalized
      55 canonical findings and opened 52 review requests. Pre-fix is now a terminal
      calibration observation; post-fix remains untouched and separately gated.
      The next [`protected post-fix receipt`](opt-005-protected-post-receipt-2026-08-07.json)
      freezes only serialize-javascript commit `16a68ab53d9626fc7c942b48a1163108fcd184c8`
      and proposes at most 14 linked batches, 350 calls, 1,000,000 provider-reported
      tokens, and $7.00, using the terminal pre-fix workload only as an operational bound.
      Authorization and protected post-fix evidence transfer remain pending; tuning and
      the offline comparison are excluded.
      The authorized [`post-fix result`](opt-005-protected-post-result-2026-08-07.json)
      completed runs 76–89 using 328 calls, 867,540 provider-reported tokens, $6.046320,
      and zero unknown usage, then stopped at the 14-batch ceiling with one deferred
      finding. The separately frozen
      [`terminal receipt`](opt-005-protected-post-terminal-receipt-2026-08-07.json) permits
      at most one batch, 26 calls, 75,000 tokens, and $0.55 for that exact row; its
      authorization and evidence transfer remain pending.
      The authorized [`terminal result`](opt-005-protected-post-terminal-result-2026-08-07.json)
      completed run 90 with 6 calls, 19,392 tokens, $0.140060, and zero unknown usage,
      draining the final row. The complete post-fix chain is runs 76–90: 334 calls,
      886,932 tokens, $6.186380, and zero deferred findings. Both protected observations
      are now terminal. The zero-provider offline comparison over terminal runs 61, 75,
      and 90 was executed and retained as a
      [`fail-closed result`](opt-005-offline-comparison-2026-08-07.json). It made no provider
      calls, but is not ready because the full lightweight chain contains two historical
      timeout attempts without token metadata. Both protected observations qualify with
      zero unknown usage. OPT-005 remains open pending one separately authorized fresh,
      clean lightweight observation; unknown calls will not be discarded to force closure.
      The [`clean lightweight receipt`](opt-005-clean-lightweight-receipt-2026-08-07.json)
      freezes a byte-identical isolated source alias and proposes at most 50 linked batches,
      400 calls, 1,200,000 provider-reported tokens, and $8.00. The run must create a new
      same-store repository identity and parentless root with zero checkpoint reuse.
      Authorization and bounded evidence transfer remain pending; protected execution,
      tuning, historical repair, and the offline rerun are excluded.
      The authorized [`clean result`](opt-005-clean-lightweight-result-2026-08-07.json)
      completed runs 91–105 under new identity `snapshot-884a968b`: a parentless root,
      zero reused detection calls, 331 calls, 882,103 provider-reported tokens, $6.032215,
      zero unknown usage, and zero deferred findings. It qualifies as the replacement
      lightweight observation. The zero-provider comparison over terminal runs 105, 75,
      and 90 was retained as a distinct [`clean ready result`](opt-005-offline-comparison-clean-2026-08-07.json).
      All three logical scan chains qualify with zero unknown usage and no deferred findings.
      Peak per-batch utilization was 38.67% of the 75-call ceiling and 46.59% of the
      250,000-token ceiling. OPT-005 is closed at its approved descriptive scope with no
      operational limit change; any future limit change requires a new scope decision.

   B. OPT-006 — Provider dollar-cost reporting — implemented — owner: reliability
      engineering — source: `../project-priorities.md` and the frozen
      [`2026-08-01 pricing snapshot`](opt-006-provider-pricing-2026-08-01.json). Anthropic's
      official model-specific table supplies standard global Claude API input, output, and
      cache-read prices for the configured `claude-opus-4-8`. Run and stage projections
      price only authoritative recorded tokens. Unknown usage, unlisted providers/models,
      cache writes without a recorded TTL, and alternate pricing modes remain visibly
      unavailable; taxes and negotiated discounts are excluded. Implemented — DoD impact: none.

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
      frameworks, languages, and cross-file flows — implemented at initial
      evidence-qualified scope — owner: AppSec engineering — source:
      `../security-claim-certificates.md` and `../triage-accuracy-roadmap.md`. The specific
      activation evidence is the human-reviewed RailsGoat CWE-502 target at pinned commit
      `0222f7da3406ba3ab637bc6d24ae9366b5f0a680`. The frozen
      [`Ruby protocol`](opt-008-ruby-deserialization-protocol-2026-08-01.json) adds one
      deliberately narrow Ruby certificate: exact `Marshal.load` over a literal-symbol
      `params` element, optionally wrapped once by exact `Base64.decode64`. Producer and
      independent checker both use tree-sitter, claim/verifier versions advance to v11, and
      five external-answer-key controls cover two positives plus constant, aliased receiver,
      and alternate-parser negatives. Forged text, a generic `.load`, and non-`params`
      sources are independently refuted. Routing, authentication, gadget availability,
      exploitability, and other Ruby loaders remain explicit non-claims. Further mechanism
      expansion requires new specific miss evidence. Implemented offline — DoD impact: none.

   C. OPT-009 — In-family/out-of-family novelty prioritization — deferred/data-gated —
      owner: AppSec/ML evaluation — source: `../project-priorities.md` — activate after
      enough manually reviewed LLM findings demonstrate held-out benefit — DoD impact: none.

   D. OPT-010 — Agentic falsification — deferred — owner: AppSec architecture — source:
      `../agentic-escalation-gate.md` — activate only after every documented safety and
      evaluation prerequisite passes — DoD impact: none.

IV. Quantitative enrichment

   A. OPT-011 — Sourced correction of organization-frequency allocation — completed
      — owner: quantitative-methodology — source: `../quantitative-integrity-audit.md` —
      long-term activation requires a defensible allocation/decomposition. The MVP separately
      gates affected output as experimental and not decision-grade — DoD impact: MVP
      presentation gate completed; richer model remains optimization. The dated
      [`methodology decision`](opt-011-methodology-decision-2026-08-07.json) now specifies
      one `organization_all_event` modeling unit that consumes the IRIS organization rate
      exactly once. Findings remain auditable membership and cannot allocate or multiply
      frequency; scenario attribution and remediation deltas remain unavailable. Runtime is
      unchanged pending the ten-condition PR 2 acceptance contract in
      [`organization-frequency-methodology.md`](../organization-frequency-methodology.md).
      The [`implementation result`](opt-011-implementation-result-2026-08-07.json) now
      records `organization_all_event_v1`: one marked modeling unit, one IRIS frequency
      stream, neutral organization defaults or explicit `*` overrides, immutable historical
      semantics, and aligned simulation/audit/report surfaces. OPT-011 is closed; category
      attribution and remediation deltas remain unavailable and OPT-014 remains data-gated.

   B. OPT-012 — Dated cached EPSS/KEV enrichment — implemented — owner: threat-data
      engineering — source: `../prior-scope-roadmap.md`. The frozen
      [`source/cache protocol`](opt-012-threat-intel-protocol-2026-08-01.json) uses FIRST's
      official EPSS API and CISA's official KEV JSON feed for real CVEs extracted from
      repository findings. `threat-enrich --refresh` is the only network path; it validates
      required source fields and numeric ranges before atomically replacing a repo-bound mode-0600
      cache. Offline reads report current, stale, missing, or invalid with a documented
      48-hour freshness window. Dated EPSS probability/percentile and KEV catalog/date-added/
      due-date/ransomware fields appear as informational scenario threat labels only. They
      do not change finding validity, severity, conditional frequency, magnitude, or deal
      risk, avoiding double counting while OPT-011 remains methodology-gated. Implemented —
      DoD impact: none.

   C. OPT-013 — Prior temporal metadata and population applicability — implemented — owner:
      quantitative-methodology — source: `../prior-scope-roadmap.md` and IRIS 2022's
      Methodology and Firmographics section. Both configured IRIS priors now record the
      report's July 2022 Advisen feed release as effective date and its exact 2012–2021
      study window as data vintage. Population and epistemic limitations remain unchanged;
      no distribution input or quantitative result changed. Implemented — DoD impact: none.

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

   B. OPT-016 — Remove SHAP/Matplotlib pending-deprecation noise — implemented — owner:
      test infrastructure — source: the 2026-07-28 fast-lane run completed with
      three warnings from SHAP's use of deprecated Matplotlib colormap mutation methods.
      SHAP 0.52.0 still emits the three warnings with Matplotlib 3.11.1. The classifier now
      suppresses only those exact `set_bad`, `set_over`, and `set_under`
      `PendingDeprecationWarning` messages, only while importing SHAP. It does not patch
      third-party code or hide unrelated warnings. Focused CLI, triage, and deterministic
      tests complete without warning noise — activation satisfied after MVP closure;
      implemented — DoD impact: none.

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

   A. OPT-022 — First-class scanner execution contract — implemented — owner:
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

   E. OPT-026 — Rerun and qualify historical scanner evidence — implemented —
      owner: detection evaluation — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` — mark the three identified
      historical zero-result Semgrep artifacts coverage-invalid without deleting them, then
      rerun material historical snapshots through the pinned, canary-qualified adapters.
      Report candidate and status deltas; do not retroactively turn newly emitted candidates
      into labels, ground truth, or evaluation positives. The project-owner-approved
      [`frozen protocol`](opt-026-historical-scanner-remeasurement-protocol-2026-07-29.json)
      records all three immutable source snapshots, marks their byte-identical historical
      SARIF as coverage-invalid without modifying it, requires the full deployment canary,
      and freezes a Semgrep-only one-to-one rerun with digest-backed raw retention. Results
      were produced in a separate PR and cannot enter labels, ground truth, classifier
      scoring, or review acquisition. The full four-tool canary passed with zero persisted
      findings. All three snapshot digests matched and the pinned Semgrep 1.170.0 reruns
      completed: 3,862 verified targets produced 571 unadjudicated candidates, changing all
      three records from ambiguous historical zeros to qualified nonzero measurements. The
      digest-backed [`result receipt`](opt-026-historical-scanner-remeasurement-results-2026-07-29.json)
      retains every status and delta while the original SARIF remains unchanged. Activation:
      satisfied after OPT-025; remeasurement complete — DoD impact: none.

   F. OPT-027 — RepoAuditor-owned supplemental Semgrep pack — implemented at initial
      evidence-qualified scope — owner: AppSec detection engineering — source:
      `../codecov-node-positive-acquisition-2026-07-29.json` — add a narrow reviewed pack for
      high-value sinks the public rules demonstrably miss, beginning with variable or
      concatenated shell execution and paired vulnerable/patched controls; consider direct
      SQL construction, URL-fetch SSRF, unsafe archive extraction, and filesystem traversal
      only with equally defensible controls. Supplemental matches remain review candidates,
      not automatic actionable findings. Activation: after OPT-024 pins the baseline and
      OPT-026 establishes corrected historical behavior. The project-owner-approved
      [`OPT-027/028 protocol`](opt-027-028-supplemental-differential-protocol-2026-07-29.json)
      freezes one initial JavaScript/TypeScript dynamic shell-execution rule, four
      manufactured controls, the codecov-node pre/post qualification target, and four
      observational acquisition pairs before the rule exists. The official and supplemental
      configurations must execute as separately attributable production-adapter passes with
      independent provenance. The first owned rule is now promoted: all four manufactured
      controls passed, the codecov-node target classified `vulnerable_only_recovery`, and
      four observational acquisition pairs retained their official and supplemental deltas.
      The first attempt is preserved because Python/Ruby language-inapplicability was
      initially reported as failed; the corrected adapter reports `not-applicable` and the
      complete rerun passed every frozen criterion. The official and supplemental passes now
      retain separate configuration identity, digest, rule count, SARIF, status, and source
      count, and the required deployment gate exercises the exact owned pack. Receipt:
      [`qualification results`](opt-027-028-supplemental-differential-results-2026-07-29.json);
      broader rule families remain separately evidence-gated — DoD impact: none.

   G. OPT-028 — Advisory-target pre/post differential checks — implemented — owner: detection
      evaluation — source:
      `../codecov-node-positive-acquisition-2026-07-29.json` and
      `../semgrep-execution-audit-2026-07-29.json` — classify each frozen target as
      vulnerable-only recovery, stable pre/post mechanism signal, patched-only signal, or
      complete miss. Never count a signal that persists after the isolated patch as precise
      target recovery merely because its file/citation overlaps; preserve unrelated
      candidates as unadjudicated. The generic differential harness now requires exact rule,
      file, citation, and frozen-line agreement for target recovery and separately reports
      exact-identity stable, pre-only, and post-only unrelated candidates. Regression tests
      cover all four target classifications and near-miss rejection. The qualified run
      classified codecov-node as vulnerable-only while preserving three other supplemental
      pre-fix signals and one post-fix signal as unrelated and unadjudicated; aggregate count
      differences were not transferred into target recovery. Activation satisfied alongside
      OPT-027 qualification; implemented — DoD impact: none.

   H. OPT-029 — Candidate explosion and repetition controls — implemented — owner:
      AppSec workflow engineering — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` — the corrected bounded run
      produced 1,941 raw candidates. Add disclosed, deterministic collapse by exact pre/post
      identity, rule/normalized sink/location deduplication, repeated-family caps per
      engagement, and explicit generated/vendor/docs/example path policy. Preserve raw
      artifacts and publish every suppression count; never suppress by predicted outcome or
      hidden answer key. The project-owner-approved PR 1 protocol freezes acquisition-only
      application, a complete monotonic funnel, narrow identities, a two-per-family/
      engagement cap, and three disclosed path tiers. Pure contract primitives and replay
      tests do not alter raw evidence. PR 2 integrates the contract as acquisition schema v3,
      retains v1/v2 loading, exposes explicit pair/path/family controls and durable output,
      and publishes every funnel delta plus input/path/hashed-family provenance. A fresh
      deterministic run reproduced the exact 1,941 candidates with healthy scanner statuses;
      retained raw and complete funnel artifacts close the prior aggregate-only gap. The
      replay collapsed 908 stable pre/post records, 7 exact duplicates, and 80 over-cap
      family repeats before engagement balancing, while preserving all unadjudicated raw
      evidence. Receipts:
      [`protocol`](opt-029-acquisition-funnel-protocol-2026-07-29.json);
      [`results`](opt-029-acquisition-funnel-results-2026-07-29.json).
      Activation satisfied before the next large human-review packet; implemented —
      DoD impact: none.

   I. OPT-030 — Per-tool capability and applicability matrix — implemented —
      owner: detection architecture — source:
      `../deterministic-tool-deployment-audit-2026-07-29.json` — publish the mechanisms,
      ecosystems, manifest/source prerequisites, expected strengths, known blind spots, and
      meaning of `complete`, `empty`, and `not-applicable` for every deterministic tool.
      Keep deployment health separate from recall/precision claims and link each capability
      statement to a control or retained measurement. The published human-readable and
      machine-readable matrices cover all five production scanner identities, all seven
      execution statuses, actual input/applicability boundaries, strengths, blind spots,
      canaries, configuration provenance, and retained evidence. They explicitly separate
      deployment health from detection claims and disclose that current `pip-audit`
      production behavior is root `requirements*.txt` only, narrower than an older audit
      narrative. A consistency test binds scanner/status coverage and evidence links to the
      production contract. Matrix:
      [`capability and applicability matrix`](../scanner-capability-matrix.md) and
      [`machine-readable contract`](../scanner-capability-matrix.json). Activation
      satisfied after OPT-026/OPT-028; implemented — DoD impact: none.

   J. OPT-031 — Bind SCA applicability declarations to executable behavior — implemented —
      owner: deterministic detection — source: the OPT-030 capability-matrix correction.
      Replace the unused `_MANIFEST_GLOBS` declaration, which named lockfiles the adapter
      never submitted to pip-audit, with separate constants for pip-audit root-manifest
      selection and OSV's recursive explicit fallback. Both executable paths now consume
      their declared patterns, and regression coverage proves pip-audit selects only root
      `requirements*.txt` while excluding nested requirements and unsupported lockfiles.
      This is contract hardening, not a claim of expanded manifest coverage; broader Python
      lockfile support remains outside the adapter until an underlying supported execution
      path is designed and qualified. Implemented — DoD impact: none.

   K. OPT-032 — Correct OSV explicit-fallback target evidence — implemented — owner:
      deterministic detection — source: OPT-030/OPT-031 contract review. A successful
      explicit `requirements*.txt` fallback previously changed `target_count` to the number
      of submitted manifests while leaving `target_count_basis` as `submitted-root`.
      Scanner state now records the active basis and emits `submitted-manifests` for that
      partial path, with a behavioral regression over the real adapter command sequence.
      Implemented offline — DoD impact: none.

   L. OPT-033 — Retain explicit not-applicable reasons — implemented — owner: reliability
      engineering — source: scanner zero-review policy. `ScannerExecution` now requires
      `applicability_detail` whenever status is `not-applicable`. Supplemental Semgrep,
      pip-audit, and both OSV no-source paths retain the missing production prerequisite;
      CLI evidence displays it. This distinguishes attributable inapplicability from an
      unexplained zero without repurposing failure detail. Implemented offline — DoD
      impact: none.

   M. OPT-034 — Enforce scanner target-count bases as code — implemented — owner: detection
      architecture — source: OPT-030 machine contract. The runtime execution model now
      rejects a known scanner using a target-count basis outside its declared capability.
      Schema v2 represents bases as structured arrays and a consistency test requires exact
      equality with the runtime allowlist, including OSV's root and manifest modes.
      Implemented offline — DoD impact: none.

   N. OPT-035 — Canonical optimization lifecycle ledger — implemented — owner: project
      governance — source: repeated post-merge backlog reassessments. The schema-v1
      [`status ledger`](optimization-status.json) enumerates every OPT from 001 through 035,
      assigns exactly one `closed` or `open` state, records the activation gate for every
      open item, and provides a contiguous post-035 priority order. Tests reject missing or
      duplicate IDs, incorrect summary totals, ungated open items, noncontiguous priorities,
      and disagreement with the authoritative register headings. Closed means the approved
      bounded scope is complete; optional expansion requires a new scope decision.
      Implemented offline — DoD impact: none.

   O. Add the next proposed improvement as `OPT-036`; do not place it directly into the MVP
      recovery plan unless the project owner explicitly changes the DoD.
