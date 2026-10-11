# Phase 13 Corrective Audit — Metric Separation and Forecast Horizon Semantics

**Decision:** Corrective findings implemented and verified at repository/CI level.  
**Implementation commit:** `c22ce871ac61cc3bca3738ec7ce0c9bdc58e3778`  
**CI:** https://github.com/LloydCoder/AURONTRA/actions/runs/38105256437  
**Secret/history/archive scan:** https://github.com/LloydCoder/AURONTRA/actions/runs/38105256448  
**Pull request:** https://github.com/LloydCoder/AURONTRA/pull/11

## Findings corrected

1. A configurable temporal horizon could have been represented under a fixed 72-hour field name. Forecast output now always includes `predicted_score`; `predicted_score_72h` is included only for the exact 72-hour horizon. Evaluation cases record the actual horizon.
2. The anomaly benchmark previously reported only the combined result of the Isolation Forest and the 95% hard-threshold override. Predictor output now separates `model_is_anomaly` from the combined decision, and the report contains `model_only` and `combined_policy` metric sets. Legacy top-level metrics remain for compatibility and explicitly represent the combined operational decision.

## Verification

- **411 passed, 1 skipped**, **85.19% total coverage**.
- Clean SQLite migration, Python compile, PostgreSQL tenant RLS and backup/restore passed.
- Secret/history/archive scan passed.
- Deployment was skipped. No production model, dataset or prediction service was exercised.

## Residual limits

- The metrics use synthetic fixtures and test doubles; they do not establish real-world model quality.
- No labeled production holdout, calibration study, category-specific operating threshold or drift-monitoring result is available.
- The 95% override remains a heuristic; it must be evaluated independently and should not be interpreted as a calibrated probability.
- The 72-hour output remains a linear trend heuristic. CI success is not a prediction-quality guarantee.

## Research references

- NIST AI RMF 1.0 MEASURE function: https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
- scikit-learn evaluation guidance: https://scikit-learn.org/stable/modules/model_evaluation.html
- scikit-learn model persistence guidance: https://scikit-learn.org/stable/model_persistence.html

The corrective audit closes the two report-semantics defects. Phase 13 remains accepted at code/CI level only; production predictive validity is unproven.
