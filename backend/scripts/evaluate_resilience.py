#!/usr/bin/env python3
"""Run a reproducible, offline Aurontra resilience evaluation.

Input JSON schema:
{
  "label_source": "documented label provenance",
  "split_strategy": "documented held-out split strategy",
  "training_baseline": [{"cpu_percent": 20, "memory_percent": 30, "disk_percent": 40}, ...],
  "evaluation_samples": [{"metrics": {...}, "label": 0}, ...],
  "temporal_cases": [{"case_id": "optional", "series": [...], "actual_score": 80}, ...]
}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from resilience.benchmark import evaluate_anomaly_detector, evaluate_temporal_forecasts


def _load_input(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read evaluation input: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Evaluation input must be a JSON object.")
    allowed = {
        "label_source", "split_strategy", "training_baseline",
        "evaluation_samples", "temporal_cases", "contamination", "n_estimators",
    }
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"Unknown top-level input fields: {', '.join(sorted(unknown))}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Path to a documented JSON benchmark dataset")
    parser.add_argument("--output", type=Path, required=True, help="Destination JSON report")
    args = parser.parse_args()

    try:
        data = _load_input(args.input)
        evaluation = data.get("evaluation_samples")
        if not isinstance(evaluation, list):
            raise ValueError("evaluation_samples must be a list.")
        metrics = [item.get("metrics") for item in evaluation if isinstance(item, dict)]
        labels = [item.get("label") for item in evaluation if isinstance(item, dict)]
        if len(metrics) != len(evaluation) or len(labels) != len(evaluation):
            raise ValueError("Every evaluation sample must include metrics and label.")
        report = {
            "report_schema_version": "aurontra.resilience-benchmark-report.v1",
            "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
            "anomaly_evaluation": evaluate_anomaly_detector(
                data.get("training_baseline"),
                metrics,
                labels,
                label_source=data.get("label_source", ""),
                split_strategy=data.get("split_strategy", ""),
                contamination=data.get("contamination", 0.05),
                n_estimators=data.get("n_estimators", 100),
            ),
        }
        temporal_cases = data.get("temporal_cases", [])
        if temporal_cases:
            report["temporal_evaluation"] = evaluate_temporal_forecasts(temporal_cases)
        canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    except (ValueError, TypeError, KeyError, OSError) as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote offline evaluation report to {args.output}")
    print(f"Report SHA-256: {report['report_sha256']}")
    print("Production validation: false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
