"""Calibrated triage classifier: RandomForest vs XGBoost, compared and calibrated.

Implements the SAST alert-quality / actionable-warning (AWI) approach: learn P(finding
is actionable) from labelled features, but treat *calibration* as first-class — a raw
tree ensemble's scores are not probabilities, and triage feeds those probabilities into
the downstream Bernoulli finding-validity gate, so they must mean what they say.

Pipeline per `train`:
  1. Fit both a RandomForest and an XGBoost classifier.
  2. Wrap each in probability calibration (isotonic when data is plentiful, Platt/sigmoid
     otherwise) via `CalibratedClassifierCV`.
  3. Evaluate on a held-out split with **precision-recall (average precision) and Brier
     score — never accuracy** (the classes are imbalanced; accuracy is misleading).
  4. Select the better model by Brier (tie-break: higher average precision), refit on
     all data, and build a SHAP `TreeExplainer` for per-finding attribution.

Output per finding: calibrated P(actionable), a rank, and the top-3 feature
attributions (SHAP contributions where available, impurity importance as a fallback).
Triage ranks and may suppress (demote below `action_threshold`); it never deletes a
finding — suppressed findings are persisted with their rank + attribution.

Real-label validation becomes engagement-grouped only after both the existing 40-label
gate and an eight-engagement gate are met. Eight is the minimum because a 25% grouped
holdout then contains at least two whole engagements and leaves six for training; a
one-repository test set would be an anecdote presented as a generalization estimate. Until
then, the prior row-random real holdout remains available but is explicitly labelled with
the group-count shortfall. No grouped statistic is fabricated from insufficient breadth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import sklearn
import xgboost
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from xgboost import XGBClassifier

from ..config import Config, get_config
from ..store import db
from ..store.models import (
    FalsificationStatus,
    Finding,
    TriageFeatureRecord,
    TriageModelRun,
    TriageResult,
)
from . import labels as triage_labels
from . import priors as triage_priors
from . import training
from .features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    SarifFinding,
    build_repo_context,
    extract_feature_vector,
    git_churn,
    load_sarif,
    sarif_severity,
    sarif_tool_confidence,
)


@dataclass
class ModelEvaluation:
    """Held-out metrics for one candidate model — PR/Brier, deliberately not accuracy."""

    model_name: str
    average_precision: float  # area under the precision-recall curve
    brier: float              # calibration quality (lower is better)
    calibration: str          # "isotonic" | "sigmoid"
    # Whether the held-out set was carved from *real* labels (an honest real-performance
    # number) or from the synthetic corpus (a statement about the generator, never
    # presented as real performance). Flagged so the two are never conflated.
    eval_on: str = "synthetic"   # "real" | "synthetic"
    n_eval: int = 0              # size of the held-out set behind these metrics
    split_strategy: str = "synthetic_row_random"
    split_detail: str = ""


MIN_GROUPED_ENGAGEMENTS = 8


def _holdout_split(
    y: np.ndarray, real_mask: np.ndarray, min_real_holdout: int, seed: int,
    engagement_groups: np.ndarray | None = None,
    evaluation_mask: np.ndarray | None = None,
) -> tuple[np.ndarray, np.ndarray, str, str, str]:
    """Pick train/test indices, preferring a REAL held-out set when there are enough.

    Returns indices, evaluation basis, split strategy, and an explicit availability detail.
    When `real_mask` marks >= `min_real_holdout`
    real rows with both classes present, the test set is a stratified 25% sample of the
    *real* rows and everything else (remaining real + all synthetic) trains — so the
    reported PR/Brier are measured on real labels. Otherwise it degrades to a stratified
    split of the whole corpus, flagged `eval_on='synthetic'` (dominated by / only synthetic
    — a generator-quality number, not a real-performance claim).
    """
    n = len(y)
    all_idx = np.arange(n)
    eligible_mask = real_mask if evaluation_mask is None else np.asarray(evaluation_mask, dtype=bool)
    real_idx = np.where(eligible_mask)[0]
    if (min_real_holdout > 0 and len(real_idx) >= min_real_holdout
            and len(np.unique(y[real_idx])) == 2):
        groups = (np.asarray(engagement_groups, dtype=object)[real_idx]
                  if engagement_groups is not None else np.full(len(real_idx), ""))
        distinct_groups = len(set(groups) - {""})
        if distinct_groups >= MIN_GROUPED_ENGAGEMENTS:
            # Try deterministic variants until both sides contain both classes. Grouping
            # is never weakened to make a convenient score appear.
            for offset in range(20):
                splitter = GroupShuffleSplit(
                    n_splits=1, test_size=0.25, random_state=seed + offset
                )
                group_train, group_test = next(splitter.split(real_idx, y[real_idx], groups))
                real_train, te_idx = real_idx[group_train], real_idx[group_test]
                if len(np.unique(y[real_train])) == 2 and len(np.unique(y[te_idx])) == 2:
                    tr_idx = np.setdiff1d(all_idx, te_idx)
                    return (
                        tr_idx, te_idx, "real", "engagement_grouped",
                        f"grouped holdout active ({distinct_groups} engagements)",
                    )
        _, te_idx = train_test_split(
            real_idx, test_size=0.25, stratify=y[real_idx], random_state=seed
        )
        tr_idx = np.setdiff1d(all_idx, te_idx)
        reason = (
            f"grouped validation not yet available ({distinct_groups} engagements, "
            f"need {MIN_GROUPED_ENGAGEMENTS})"
            if distinct_groups < MIN_GROUPED_ENGAGEMENTS
            else "grouped split could not preserve both classes in train and evaluation"
        )
        return tr_idx, te_idx, "real", "real_row_random", reason
    tr_idx, te_idx = train_test_split(
        all_idx, test_size=0.25, stratify=y, random_state=seed
    )
    return (
        tr_idx, te_idx, "synthetic", "synthetic_row_random",
        f"real-label gate not met ({len(real_idx)} labels, need {min_real_holdout}); "
        "metrics measure synthetic-generator quality, not real-world performance",
    )


def _make_base(model_name: str, seed: int):
    if model_name == "randomforest":
        return RandomForestClassifier(
            n_estimators=300, max_depth=None, min_samples_leaf=2,
            class_weight="balanced", random_state=seed, n_jobs=-1,
        )
    return XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9,
        colsample_bytree=0.9, eval_metric="logloss", random_state=seed, n_jobs=-1,
    )


@dataclass
class TriageClassifier:
    """A trained, calibrated triage model plus its model-comparison record."""

    calibrated: CalibratedClassifierCV
    attribution_model: object          # plain RF/XGB fit on all data, for SHAP
    model_name: str
    evaluations: list[ModelEvaluation]
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    _explainer: object = None

    @classmethod
    def train(
        cls,
        X: np.ndarray,
        y: np.ndarray,
        seed: int = 0,
        *,
        sample_weight: np.ndarray | None = None,
        real_mask: np.ndarray | None = None,
        engagement_groups: np.ndarray | None = None,
        evaluation_mask: np.ndarray | None = None,
        min_real_holdout: int = 0,
    ) -> "TriageClassifier":
        """Train + calibrate RF and XGB, compare on held-out PR/Brier, keep the winner.

        `sample_weight` lets the synthetic teacher be down-weighted as real labels
        accumulate (see `triage/training.py`). `real_mask` marks which rows are real: when
        at least `min_real_holdout` real rows exist (both classes present), the held-out
        eval set is carved *entirely from real rows* so PR/Brier are an honest real-
        performance number; otherwise the eval falls back to a split of the full corpus and
        is flagged `eval_on='synthetic'` — never passed off as real performance.
        """
        X = np.asarray(X, dtype=float)
        y = np.asarray(y, dtype=int)
        n = len(y)
        if sample_weight is None:
            sample_weight = np.ones(n, dtype=float)
        else:
            sample_weight = np.asarray(sample_weight, dtype=float)
        real_mask = (np.zeros(n, dtype=bool) if real_mask is None
                     else np.asarray(real_mask, dtype=bool))

        # Isotonic needs a fair amount of data to avoid overfitting the calibration
        # map; below ~1000 rows fall back to Platt scaling (sigmoid).
        method = "isotonic" if n >= 1000 else "sigmoid"
        tr_idx, te_idx, eval_on, split_strategy, split_detail = _holdout_split(
            y, real_mask, min_real_holdout, seed, engagement_groups, evaluation_mask
        )

        evaluations: list[ModelEvaluation] = []
        for name in ("randomforest", "xgboost"):
            calibrated = CalibratedClassifierCV(
                _make_base(name, seed), method=method, cv=3
            )
            calibrated.fit(X[tr_idx], y[tr_idx], sample_weight=sample_weight[tr_idx])
            p = calibrated.predict_proba(X[te_idx])[:, 1]
            evaluations.append(
                ModelEvaluation(
                    model_name=name,
                    average_precision=float(average_precision_score(y[te_idx], p)),
                    brier=float(brier_score_loss(y[te_idx], p)),
                    calibration=method,
                    eval_on=eval_on,
                    n_eval=int(len(te_idx)),
                    split_strategy=split_strategy,
                    split_detail=split_detail,
                )
            )

        # Winner: lowest Brier, tie-broken by highest average precision.
        winner = min(evaluations, key=lambda e: (e.brier, -e.average_precision))
        winning_name = winner.model_name

        # Refit the calibrated model on ALL data (weighted) for deployment.
        final = CalibratedClassifierCV(_make_base(winning_name, seed), method=method, cv=3)
        final.fit(X, y, sample_weight=sample_weight)
        # Separate plain model on all data for SHAP attribution (calibration wrappers
        # don't expose a single tree ensemble cleanly).
        attribution_model = _make_base(winning_name, seed)
        attribution_model.fit(X, y, sample_weight=sample_weight)

        clf = cls(
            calibrated=final,
            attribution_model=attribution_model,
            model_name=winning_name,
            evaluations=evaluations,
        )
        clf._build_explainer()
        return clf

    def _build_explainer(self) -> None:
        try:
            import shap

            self._explainer = shap.TreeExplainer(self.attribution_model)
        except Exception:
            self._explainer = None  # fall back to global importances

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Calibrated P(actionable) for each row."""
        X = np.asarray(X, dtype=float)
        return self.calibrated.predict_proba(X)[:, 1]

    def attributions(self, X: np.ndarray, top_k: int = 3) -> list[list[dict]]:
        """Top-k feature attributions per row (SHAP if available, else importances)."""
        X = np.asarray(X, dtype=float)
        if self._explainer is not None:
            try:
                return self._shap_attributions(X, top_k)
            except Exception:
                pass
        return self._importance_attributions(X, top_k)

    def _shap_attributions(self, X: np.ndarray, top_k: int) -> list[list[dict]]:
        values = self._explainer.shap_values(X)
        arr = np.asarray(values)
        # Normalize to (n_samples, n_features) contributions for the positive class.
        if arr.ndim == 3:                      # (n, features, classes) or (classes, n, features)
            arr = arr[..., -1] if arr.shape[-1] <= 4 else arr[-1]
        out: list[list[dict]] = []
        for i in range(X.shape[0]):
            row = arr[i]
            order = np.argsort(np.abs(row))[::-1][:top_k]
            out.append([
                {"feature": self.feature_names[j], "value": float(X[i, j]),
                 "contribution": float(row[j])}
                for j in order
            ])
        return out

    def _importance_attributions(self, X: np.ndarray, top_k: int) -> list[list[dict]]:
        importances = np.asarray(getattr(self.attribution_model, "feature_importances_",
                                         np.ones(len(self.feature_names))))
        order = np.argsort(importances)[::-1][:top_k]
        return [
            [
                {"feature": self.feature_names[j], "value": float(X[i, j]),
                 "contribution": float(importances[j])}
                for j in order
            ]
            for i in range(X.shape[0])
        ]


@dataclass
class TriageOutcome:
    """Result of triaging a repo: ranked findings + the model-comparison record."""

    repo_id: str
    model_name: str
    evaluations: list[ModelEvaluation]
    ranked: list[TriageResult]
    action_threshold: float
    n_suppressed: int
    # Closed-loop training state: how many real labels trained this run and the synthetic
    # teacher's remaining share of the training mass (1.0 cold start -> 0.0 once real data
    # dominates / is past the cutoff). Surfaced so the CLI can show the loop maturing.
    n_real_labels: int = 0
    synthetic_share: float = 1.0
    synthetic_dropped: bool = False


# Severity / tool-confidence mapping lives in `features` so the detect-stage SAST
# adapter and this classifier derive a deterministic tool's signal the same way.
_severity_of = sarif_severity
_tool_confidence = sarif_tool_confidence


def _discover_sarif(repo_id: str, config: Config) -> Path | None:
    """Find a SARIF file for a repo by convention (raw dir, then latest snapshot)."""
    candidates = [
        config.raw_dir / repo_id / "sast.sarif",
        config.raw_dir / repo_id / "semgrep.sarif",
    ]
    try:
        from ..ingest import latest_snapshot

        snapshot_path, commit = latest_snapshot(config, repo_id)
        candidates += [
                       config.resolve(config.paths.data_dir) / "artifacts" / repo_id
                       / commit / "detect" / "semgrep.sarif",
                       snapshot_path / "sast.sarif",
                       snapshot_path / ".repoauditor" / "sast.sarif"]
    except Exception:
        pass
    for path in candidates:
        if path.is_file():
            return path
    return None


def _scanner_versions(path: Path) -> dict[str, str]:
    """Read only scanner versions explicitly present in SARIF producer metadata."""
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    versions: dict[str, str] = {}
    for run in document.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        name = driver.get("name")
        version = driver.get("semanticVersion") or driver.get("version")
        if name and version:
            versions[str(name)] = str(version)
    return versions


def _persist_finding(finding: SarifFinding, repo_id: str, config: Config,
                     existing: dict[tuple, int]) -> int:
    """Insert a SARIF finding as a Finding (source_tool), reusing an existing row.

    Idempotent per (file, line_start, rule_id) so re-running triage doesn't duplicate
    findings. Deterministic-tool findings enter with `unresolved` status — triage ranks
    them; the later falsify stage decides survival.
    """
    title = finding.rule_name or finding.rule_id
    key = (finding.file, finding.line_start, title)
    if key in existing:
        return existing[key]
    # Carry the CWE into the description so downstream stages (e.g. risk-quant scenario
    # categorization) can see it — the canonical Finding has no dedicated CWE column.
    cwe_tag = f" [CWE-{finding.cwe}]" if finding.cwe else ""
    description = f"{finding.message} (rule {finding.rule_id}){cwe_tag}"
    row = Finding(
        repo_id=repo_id,
        title=title,
        file=finding.file,
        line_start=finding.line_start,
        line_end=max(finding.line_end, finding.line_start),
        citation_snippet=finding.snippet or finding.message[:200] or finding.rule_id,
        source_tool=finding.tool_name,
        confidence=_tool_confidence(finding),
        severity=_severity_of(finding),
        falsification_status=FalsificationStatus.UNRESOLVED,
        description=description,
    )
    fid = db.insert_finding(row, config)
    existing[key] = fid
    return fid


def triage_repo(
    repo_id: str,
    config: Config | None = None,
    *,
    sarif_path: str | Path | None = None,
    action_threshold: float = 0.5,
    seed: int = 0,
    classifier: TriageClassifier | None = None,
) -> TriageOutcome:
    """Triage a repo's SAST findings: rank by calibrated P(actionable), persist results.

    Library entry point behind `repoauditor triage <repo-id>` (the CLI stays thin).
    Steps: load SARIF -> derive labels from downstream falsify/review outcomes (the closed
    loop) -> refresh per-rule Beta-Binomial priors from accumulated labels -> build features
    (the store/git signals are one seam where *real* labels influence scoring) -> assemble a
    training corpus that blends the synthetic teacher with real labelled feature-rows,
    synthetic shrinking as real data grows (triage/training.py) -> train+compare RF/XGB ->
    score, rank, persist a `TriageResult` and the feature vector per finding. Nothing is
    deleted; findings below `action_threshold` are marked `suppressed` but kept.
    """
    config = config or get_config()

    resolved = Path(sarif_path) if sarif_path else _discover_sarif(repo_id, config)
    if resolved is None or not Path(resolved).is_file():
        raise FileNotFoundError(
            f"no SARIF findings for repo '{repo_id}'. Expected a SAST SARIF file "
            f"(e.g. {config.raw_dir / repo_id / 'sast.sarif'}) or pass sarif_path."
        )
    findings = load_sarif(Path(resolved))
    if not findings:
        return TriageOutcome(repo_id, "none", [], [], action_threshold, 0)

    # Closed loop: harvest any new falsify verdicts / review decisions (this repo's prior
    # runs and every other engagement) into TriageLabels before we build priors or train,
    # so the freshest ground truth feeds both. Manual labels are protected from overwrite.
    triage_labels.derive_labels(config)

    # Per-rule priors from accumulated labels — this is where real analyst labels feed
    # the classifier (via features), the cross-engagement learning seam.
    rule_ids = [f.rule_id for f in findings]
    rule_priors = triage_priors.refresh_rule_priors(rule_ids, config)
    default_mean = sum(triage_priors.global_prior(config)[:2])
    default_prior_mean = (triage_priors.global_prior(config)[0] / default_mean)
    rule_prior_mean = {rid: p.posterior_mean for rid, p in rule_priors.items()}
    rule_fp_rate: dict[str, float] = {}
    rule_label_count: dict[str, int] = {}
    for rid in set(rule_ids):
        fp, n = triage_priors.historical_fp_rate(rid, config)
        rule_fp_rate[rid] = fp
        rule_label_count[rid] = n

    # Best-effort git churn from the ingested snapshot (0s if not a git tree).
    churn = {}
    try:
        from ..ingest import latest_snapshot

        snapshot_path, _ = latest_snapshot(config, repo_id)
        churn = git_churn(snapshot_path, [f.file for f in findings])
    except Exception:
        churn = {}

    ctx = build_repo_context(
        findings,
        rule_prior_mean=rule_prior_mean,
        rule_fp_rate=rule_fp_rate,
        rule_label_count=rule_label_count,
        churn=churn,
        default_prior_mean=default_prior_mean,
    )
    X = np.array([extract_feature_vector(f, ctx) for f in findings], dtype=float)

    # Assemble the training corpus: the synthetic teacher blended with real accumulated
    # labels, whose share grows (and synthetic's shrinks) as real labels arrive — see
    # triage/training.py. Real labels also already influence X above via the per-rule
    # prior-mean + historical-FP-rate features; this is the third, most direct channel.
    corpus = training.assemble_training_data(config, seed=seed)
    clf = classifier or TriageClassifier.train(
        corpus.X, corpus.y, seed=seed,
        sample_weight=corpus.sample_weight, real_mask=corpus.real_mask,
        engagement_groups=corpus.engagement_groups,
        evaluation_mask=corpus.evaluation_mask,
        min_real_holdout=config.triage.min_real_labels_for_holdout_eval,
    )

    chosen_eval = next(
        (evaluation for evaluation in clf.evaluations if evaluation.model_name == clf.model_name),
        clf.evaluations[0],
    )
    model_version = xgboost.__version__ if clf.model_name == "xgboost" else sklearn.__version__
    evaluations = [
        {
            "model": evaluation.model_name,
            "average_precision": evaluation.average_precision,
            "brier": evaluation.brier,
            "calibration": evaluation.calibration,
            "eval_on": evaluation.eval_on,
            "n_eval": evaluation.n_eval,
            "split_strategy": evaluation.split_strategy,
            "split_detail": evaluation.split_detail,
        }
        for evaluation in clf.evaluations
    ]
    triage_run_id = db.insert_triage_model_run(TriageModelRun(
        repo_id=repo_id,
        model_name=clf.model_name,
        model_version=model_version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        training_label_count=corpus.n_real,
        evaluation_label_count=int(corpus.evaluation_mask.sum()),
        label_source_counts=corpus.label_source_counts,
        synthetic_share=corpus.synthetic_share,
        synthetic_dropped=corpus.synthetic_dropped,
        calibration=chosen_eval.calibration,
        evaluation_basis=chosen_eval.eval_on,
        split_strategy=chosen_eval.split_strategy,
        split_detail=chosen_eval.split_detail,
        evaluations=evaluations,
        scanner_versions=_scanner_versions(Path(resolved)),
    ), config)

    probs = clf.predict_proba(X)
    attrs = clf.attributions(X)

    existing = _existing_findings_index(repo_id, config)
    ranked_idx = np.argsort(probs)[::-1]  # highest P(actionable) first
    results: list[TriageResult] = []
    n_suppressed = 0
    for rank, i in enumerate(ranked_idx, start=1):
        fid = _persist_finding(findings[i], repo_id, config, existing)
        # Persist the exact feature vector so this finding is rejoinable to a label
        # collected later (manual or derived) — the bridge to real cross-engagement training.
        db.upsert_triage_features(
            TriageFeatureRecord(
                finding_id=fid,
                engagement=repo_id,
                rule_id=findings[i].rule_id,
                fingerprint=findings[i].fingerprint,
                features=[float(v) for v in X[i]],
                feature_names=list(FEATURE_NAMES),
            ),
            config,
        )
        suppressed = bool(probs[i] < action_threshold)
        n_suppressed += int(suppressed)
        result = TriageResult(
            finding_id=fid,
            p_actionable=float(probs[i]),
            rank=rank,
            suppressed=suppressed,
            model_name=clf.model_name,
            attributions=attrs[i],
            triage_run_id=triage_run_id,
        )
        db.upsert_triage_result(result, config)
        results.append(result)

    return TriageOutcome(
        repo_id=repo_id,
        model_name=clf.model_name,
        evaluations=clf.evaluations,
        ranked=results,
        action_threshold=action_threshold,
        n_suppressed=n_suppressed,
        n_real_labels=corpus.n_real,
        synthetic_share=corpus.synthetic_share,
        synthetic_dropped=corpus.synthetic_dropped,
    )


def _existing_findings_index(repo_id: str, config: Config) -> dict[tuple, int]:
    """Map (file, line_start, rule_id/title) -> finding_id for idempotent re-runs."""
    index: dict[tuple, int] = {}
    for f in db.list_findings(repo_id, config):
        index[(f.file, f.line_start, f.title)] = f.id
    return index
