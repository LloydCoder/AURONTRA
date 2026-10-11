# Phase 13 — Predictive Resilience Evaluation

**Status:** Implementation under CI validation. No real-world predictive-performance claim is made by this phase.

## Objective

Make anomaly and 72-hour trend outputs measurable, reproducible, and honest about their limits before they can inform operational decisions. A green unit test or synthetic fixture is not proof of predictive validity.

## Predictor input contract

- CPU, memory, and disk percentages must all be present, numeric, finite, and within 0–100. Missing values are never imputed as zero.
- `contamination` must be in (0, 0.5]; `n_estimators` must be a positive integer.
- Isolation Forest randomness is pinned for repeatable results.
- The returned `anomaly_score` and compatibility `confidence` field are uncalibrated. Evaluation reports separately show `model_only` metrics and `combined_policy` metrics so the 95% override does not hide base-model false positives/negatives. `confidence_semantics=uncalibrated_heuristic_not_probability` explicitly prevents interpreting them as calibrated probabilities.
- The deterministic 95% threshold override is a policy heuristic; it must be evaluated separately from model predictions.

## Model artifact safety

Scikit-learn model persistence uses pickle, which is executable deserialization. `save()` returns the exact artifact SHA-256. `load()` refuses to deserialize without an externally trusted expected digest and validates artifact schema/model type after digest verification. The expected digest must come from a trusted/signed deployment manifest or model registry—not an adjacent sidecar. Artifact loading remains a privileged deployment operation, not an API feature.

## Temporal forecast contract

- Every reading requires a valid ISO-8601 timezone-aware timestamp and all three metric values.
- Timestamps must be strictly increasing. Missing/invalid data is rejected rather than silently converted to zero.
- Trend slopes are fitted against elapsed hours, not sample index, so irregular collection intervals do not silently change the forecast horizon.
- Forecast output identifies `linear_trend_heuristic`, the requested horizon, data span, `calibration_status=not_calibrated`, and `production_validation=false`. The generic `predicted_score` is always emitted; the legacy `predicted_score_72h` alias is emitted only when the configured horizon is exactly 72 hours.
- A 72-hour score is a heuristic extrapolation, not an assurance that an incident will or will not occur.

## Reproducible evaluation report

`backend/resilience/benchmark.py` provides two holdout evaluators:

1. **Anomaly detector:** accuracy, precision, recall, F1, confusion matrix, false-positive/false-negative rates, Wilson 95% interval for FPR, average precision and ROC-AUC, separately for base-model predictions and the combined operational policy; training/evaluation sample counts, dataset hashes, label source and split strategy.
2. **Temporal forecast:** MAE, RMSE, mean bias, fraction within 10 score points, per-case predictions/errors, horizon and dataset hash.

`backend/scripts/evaluate_resilience.py` accepts a JSON dataset manifest and writes a canonical report with SHA-256. It requires explicit label provenance and split strategy. It rejects malformed schemas, non-finite JSON numbers, invalid labels and incomplete time series. Every report explicitly sets `production_validation=false`.

## Evaluation discipline

- Train only on the baseline dataset; evaluate on a separate labeled holdout.
- Keep normal and anomalous classes represented in anomaly evaluation.
- Report metrics and uncertainty, not a single accuracy number.
- Do not treat synthetic test fixtures as customer/production validation.
- Preserve the dataset hash, label provenance, split strategy, model configuration, feature schema and report hash with each evaluation.
- A future production promotion gate needs a representative, authorized, labeled dataset; time-separated holdout; baseline comparison; category-level false-positive/false-negative analysis; drift monitoring; and a human-approved operational threshold.

## Acceptance tests

- Strict predictor input validation and model configuration.
- Trusted digest required for pickle deserialization; tampered bytes rejected before unpickling.
- Time-aware trend slope under irregular sample intervals.
- Invalid/missing/out-of-order timestamps and missing/out-of-range metrics rejected.
- Anomaly metrics and temporal forecast error calculations are reproducible and provenance-bearing.
- CI and secret/history/archive scans green; documentation and roadmap reconciled.

## Research references

- NIST AI RMF 1.0, especially MEASURE: document evaluation methods, uncertainty, validity, limitations and monitoring: https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
- scikit-learn model evaluation and selection: keep evaluation data separate from training and select metrics appropriate to the task: https://scikit-learn.org/stable/model_selection.html and https://scikit-learn.org/stable/modules/model_evaluation.html
- scikit-learn persistence guidance warns that pickle-based artifacts must be trusted and compatible with the training environment: https://scikit-learn.org/stable/model_persistence.html
