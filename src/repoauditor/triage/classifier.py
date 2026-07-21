"""Calibrated triage classifier: RandomForest vs XGBoost, compared and calibrated.

Implements the SAST alert-quality / actionable-warning (AWI) approach: learn P(finding
is actionable) from labelled features, but treat *calibration* as first-class — a raw
tree ensemble's scores are not probabilities, and triage feeds those probabilities into
a downstream frequency prior, so they must mean what they say.

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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from ..config import Config, get_config
from ..store import db
from ..store.models import FalsificationStatus, Finding, Severity, TriageResult
from . import priors as triage_priors
from . import synthetic
from .features import (
    FEATURE_NAMES,
    SarifFinding,
    build_repo_context,
    extract_feature_vector,
    git_churn,
    load_sarif,
)


@dataclass
class ModelEvaluation:
    """Held-out metrics for one candidate model — PR/Brier, deliberately not accuracy."""

    model_name: str
    average_precision: float  # area under the precision-recall curve
    brier: float              # calibration quality (lower is better)
    calibration: str          # "isotonic" | "sigmoid"


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
    def train(cls, X: np.ndarray, y: np.ndarray, seed: int = 0) -> "TriageClassifier":
        """Train + calibrate RF and XGB, compare on held-out PR/Brier, keep the winner."""
        X = np.asarray(X, dtype=float)
        y = np.asarray(y, dtype=int)
        # Isotonic needs a fair amount of data to avoid overfitting the calibration
        # map; below ~1000 rows fall back to Platt scaling (sigmoid).
        method = "isotonic" if len(y) >= 1000 else "sigmoid"
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.25, stratify=y, random_state=seed
        )

        evaluations: list[ModelEvaluation] = []
        fitted: dict[str, CalibratedClassifierCV] = {}
        for name in ("randomforest", "xgboost"):
            calibrated = CalibratedClassifierCV(
                _make_base(name, seed), method=method, cv=3
            )
            calibrated.fit(X_tr, y_tr)
            p = calibrated.predict_proba(X_te)[:, 1]
            evaluations.append(
                ModelEvaluation(
                    model_name=name,
                    average_precision=float(average_precision_score(y_te, p)),
                    brier=float(brier_score_loss(y_te, p)),
                    calibration=method,
                )
            )
            fitted[name] = calibrated

        # Winner: lowest Brier, tie-broken by highest average precision.
        winner = min(evaluations, key=lambda e: (e.brier, -e.average_precision))
        winning_name = winner.model_name

        # Refit the calibrated model on ALL data for deployment.
        final = CalibratedClassifierCV(_make_base(winning_name, seed), method=method, cv=3)
        final.fit(X, y)
        # Separate plain model on all data for SHAP attribution (calibration wrappers
        # don't expose a single tree ensemble cleanly).
        attribution_model = _make_base(winning_name, seed)
        attribution_model.fit(X, y)

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


# --------------------------------------------------------------------------- #
# Severity mapping (deterministic tool signal -> canonical Severity)
# --------------------------------------------------------------------------- #
def _severity_of(finding: SarifFinding) -> Severity:
    ss = finding.security_severity
    if ss is not None:
        if ss >= 9.0:
            return Severity.CRITICAL
        if ss >= 7.0:
            return Severity.HIGH
        if ss >= 4.0:
            return Severity.MEDIUM
        if ss >= 0.1:
            return Severity.LOW
        return Severity.INFO
    return {"error": Severity.HIGH, "warning": Severity.MEDIUM,
            "note": Severity.LOW, "none": Severity.INFO}.get(finding.level, Severity.MEDIUM)


def _tool_confidence(finding: SarifFinding) -> float:
    """Nominal *tool* confidence (distinct from triage P(actionable))."""
    if finding.security_severity is not None:
        return min(max(finding.security_severity / 10.0, 0.0), 1.0)
    return {"error": 0.7, "warning": 0.5, "note": 0.3, "none": 0.2}.get(finding.level, 0.5)


def _discover_sarif(repo_id: str, config: Config) -> Path | None:
    """Find a SARIF file for a repo by convention (raw dir, then latest snapshot)."""
    candidates = [
        config.raw_dir / repo_id / "sast.sarif",
        config.raw_dir / repo_id / "semgrep.sarif",
    ]
    try:
        from ..ingest import latest_snapshot

        snapshot_path, _ = latest_snapshot(config, repo_id)
        candidates += [snapshot_path / "sast.sarif",
                       snapshot_path / ".repoauditor" / "sast.sarif"]
    except Exception:
        pass
    for path in candidates:
        if path.is_file():
            return path
    return None


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
    Steps: load SARIF -> refresh per-rule Beta-Binomial priors from accumulated labels
    -> build features (the store/git signals are the seam where *real* labels influence
    scoring) -> train+compare RF/XGB on the synthetic corpus (until enough real labelled
    feature-rows exist) -> score, rank, and persist a `TriageResult` per finding. Nothing
    is deleted; findings below `action_threshold` are marked `suppressed` but kept.
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

    # Train on the synthetic corpus (documented stand-in until real labelled feature
    # rows accumulate); real per-rule labels already influence X via the features above.
    clf = classifier or TriageClassifier.train(*_training_data(seed), seed=seed)

    probs = clf.predict_proba(X)
    attrs = clf.attributions(X)

    existing = _existing_findings_index(repo_id, config)
    ranked_idx = np.argsort(probs)[::-1]  # highest P(actionable) first
    results: list[TriageResult] = []
    n_suppressed = 0
    for rank, i in enumerate(ranked_idx, start=1):
        fid = _persist_finding(findings[i], repo_id, config, existing)
        suppressed = bool(probs[i] < action_threshold)
        n_suppressed += int(suppressed)
        result = TriageResult(
            finding_id=fid,
            p_actionable=float(probs[i]),
            rank=rank,
            suppressed=suppressed,
            model_name=clf.model_name,
            attributions=attrs[i],
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
    )


def _training_data(seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Synthetic training corpus (X, y). Marked synthetic at the source."""
    ds = synthetic.generate(n=2000, seed=seed)
    return ds.X, ds.y


def _existing_findings_index(repo_id: str, config: Config) -> dict[tuple, int]:
    """Map (file, line_start, rule_id/title) -> finding_id for idempotent re-runs."""
    index: dict[tuple, int] = {}
    for f in db.list_findings(repo_id, config):
        index[(f.file, f.line_start, f.title)] = f.id
    return index
